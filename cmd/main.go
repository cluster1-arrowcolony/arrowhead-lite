package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	handlers "git.ri.se/eu-cop-pilot/arrowhead-lite/api"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/auth"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/ca"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/database"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/orchestration"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/registry"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

func main() {
	var quiet = flag.Bool("quiet", false, "Disable all logging output")
	var verbose = flag.Bool("verbose", false, "Enable verbose logging")
	var disableTLS = flag.Bool("disable-tls", false, "Disable TLS even if enabled in configuration")
	flag.Parse()

	configPath := os.Getenv("ARROWHEAD_CONFIG")

	cfg, err := internal.LoadConfig(configPath)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration")
	}

	// Override logging level based on flags
	if *quiet {
		cfg.Logging.Level = "panic" // Only show panic messages
	} else if *verbose {
		cfg.Logging.Level = "debug"
	}

	// Override TLS configuration based on flags
	if *disableTLS {
		cfg.Server.TLS.Enabled = false
	}

	logger := setupLogger(cfg.Logging)
	if !*quiet {
		logger.Info("Starting Arrowhead IoT Service Mesh")
	}

	var connectionString string

	if cfg.Database.Type == "postgres" || cfg.Database.Type == "postgresql" {
		connectionString = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			cfg.Database.Host, cfg.Database.Port, cfg.Database.Username, cfg.Database.Password, cfg.Database.Name)
	} else {
		// For SQLite, use the path field or default path
		connectionString = cfg.Database.Path
		if connectionString == "" {
			connectionString = "./arrowhead.db"
		}
	}

	db, err := database.NewStorage(cfg.Database.Type, connectionString)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize database")
	}
	defer db.Close()

	registryService := registry.NewRegistry(db, logger)

	authManager := auth.NewAuthManager(db, logger, []byte(cfg.Auth.JWTSecret))
	if err := setupAuthKeys(authManager, cfg.Auth); err != nil {
		logger.WithError(err).Warn("Failed to setup auth keys, using JWT secrets only")
	}

	orchestratorService := orchestration.NewOrchestrator(db, authManager, logger)

	// Create Certificate Authority
	certificateAuthority, err := ca.NewCertificateAuthority("", "", "arrowhead123", logger)
	if err != nil {
		logger.WithError(err).Warn("Failed to initialize certificate authority")
	}

	router := setupRouter(cfg, registryService, authManager, orchestratorService, certificateAuthority, logger)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	if cfg.Server.TLS.Enabled {
		// Load CA certificates for mTLS verification
		caCertPool, err := loadTrustStore(cfg.Server.TLS.TruststoreFile)
		if err != nil {
			logger.WithError(err).Fatal("Failed to load truststore, mTLS cannot be enforced.")
		}

		// The server's certificate doesn't need to be loaded separately here if we use ListenAndServeTLS,
		// but the tls.Config is the right place for all other settings.

		tlsConfig := &tls.Config{
			// Certificates will be loaded by ListenAndServeTLS from the config file paths.
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  caCertPool,
		}
		server.TLSConfig = tlsConfig

		logger.WithFields(logrus.Fields{
			"host":      cfg.Server.Host,
			"port":      cfg.Server.Port,
			"tls":       true,
			"cert_file": cfg.Server.TLS.CertFile,
			"key_file":  cfg.Server.TLS.KeyFile,
		}).Info("Starting HTTPS server")

		go func() {
			// ListenAndServeTLS will use the server.TLSConfig and load the certs from the files.
			if err := server.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				logger.WithError(err).Fatal("Failed to start HTTPS server")
			}
		}()
	} else {
		logger.WithFields(logrus.Fields{
			"host": cfg.Server.Host,
			"port": cfg.Server.Port,
			"tls":  false,
		}).Info("Starting HTTP server")

		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.WithError(err).Fatal("Failed to start HTTP server")
			}
		}()
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Fatal("Server forced to shutdown")
	}

	logger.Info("Server exited")
}

func setupLogger(cfg internal.LoggingConfig) *logrus.Logger {
	logger := logrus.New()

	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	if cfg.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	if cfg.File != "" {
		file, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logger.WithError(err).Warn("Failed to open log file, using stdout")
		} else {
			logger.SetOutput(file)
		}
	}

	return logger
}

// Sets up the public and private authentication keys for the AuthManager.
func setupAuthKeys(authManager *auth.AuthManager, cfg internal.AuthConfig) error {
	var privateKeyPEM, publicKeyPEM []byte
	var err error

	if cfg.PrivateKeyFile != "" {
		privateKeyPEM, err = os.ReadFile(cfg.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}
	}

	if cfg.PublicKeyFile != "" {
		publicKeyPEM, err = os.ReadFile(cfg.PublicKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read public key file: %w", err)
		}
	}

	return authManager.SetKeys(privateKeyPEM, publicKeyPEM)
}

// Initializes the Gin router with all routes and middleware.
func setupRouter(
	cfg *internal.Config,
	registryService *registry.Registry,
	authManager *auth.AuthManager,
	orchestratorService *orchestration.Orchestrator,
	certificateAuthority *ca.CertificateAuthority,
	logger *logrus.Logger,
) *gin.Engine {
	if cfg.Logging.Level != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.LoggerWithWriter(logger.Writer()))

	corsConfig := cors.Config{
		AllowOrigins: cfg.Server.CORS.AllowOrigins,
		AllowMethods: cfg.Server.CORS.AllowMethods,
		AllowHeaders: cfg.Server.CORS.AllowHeaders,
		MaxAge:       12 * time.Hour,
	}
	router.Use(cors.New(corsConfig))

	h := handlers.New(registryService, authManager, orchestratorService, certificateAuthority, logger)

	router.GET("/health", h.HealthCheck)
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Arrowhead 4.x compatible endpoints (no /api/v1 prefix)
	// Service Registry endpoints
	serviceRegistry := router.Group("/serviceregistry")
	{
		// Management API endpoints
		mgmt := serviceRegistry.Group("/mgmt")
		{
			// All system-related endpoints are under /systems
			systems := mgmt.Group("/systems")
			{
				// Public read-only routes
				systems.GET("", h.ListSystems)
				systems.GET("/:id", h.GetSystemByID)

				// Authenticated write routes
				if cfg.Server.TLS.Enabled {
					systems.POST("", h.AuthMiddleware(), h.RegisterSystem)
					systems.DELETE("/:id", h.AuthMiddleware(), h.UnregisterSystemByID)
				} else {
					systems.POST("", h.RegisterSystem)
					systems.DELETE("/:id", h.UnregisterSystemByID)
				}
			}

			// All service-related endpoints are under /services
			services := mgmt.Group("/services")
			{
				// Public read-only routes
				services.GET("", h.ListServices)
				services.GET("/:id", h.GetServiceByID)

				// Authenticated write routes
				if cfg.Server.TLS.Enabled {
					services.POST("", h.AuthMiddleware(), h.RegisterServiceMgmt)
					services.DELETE("/:id", h.AuthMiddleware(), h.UnregisterServiceByID)
				} else {
					services.POST("", h.RegisterServiceMgmt)
					services.DELETE("/:id", h.UnregisterServiceByID)
				}
			}
		}

		// Public registration endpoints
		serviceRegistry.POST("/register-system", h.RegisterSystemPublic)
		serviceRegistry.DELETE("/unregister-system", h.UnregisterSystemPublic)

		// Apply authentication middleware conditionally for service registration
		if cfg.Server.TLS.Enabled {
			serviceRegistry.POST("/register", h.AuthMiddleware(), h.RegisterService)
			serviceRegistry.DELETE("/unregister", h.AuthMiddleware(), h.UnregisterService)
		} else {
			serviceRegistry.POST("/register", h.RegisterService)
			serviceRegistry.DELETE("/unregister", h.UnregisterService)
		}
	}

	// Authorization endpoints
	authorization := router.Group("/authorization")
	{
		authMgmt := authorization.Group("/mgmt")
		{
			// Apply authentication middleware conditionally based on TLS configuration
			if cfg.Server.TLS.Enabled {
				authMgmt.POST("/intracloud", h.AuthMiddleware(), h.AddAuthorization)
				authMgmt.DELETE("/intracloud/:id", h.AuthMiddleware(), h.RemoveAuthorization)
			} else {
				authMgmt.POST("/intracloud", h.AddAuthorization)
				authMgmt.DELETE("/intracloud/:id", h.RemoveAuthorization)
			}

			// Public, read-only routes
			authMgmt.GET("/intracloud", h.ListAuthorizations)
		}
	}

	// Orchestrator endpoints
	orchestrator := router.Group("/orchestrator")
	{
		// Apply authentication middleware conditionally based on TLS configuration
		if cfg.Server.TLS.Enabled {
			orchestrator.POST("/orchestration", h.AuthMiddleware(), h.Orchestrate)
		} else {
			orchestrator.POST("/orchestration", h.Orchestrate)
		}
	}

	router.Static("/static", "./web/static")
	router.LoadHTMLGlob("web/templates/*")

	router.GET("/", func(c *gin.Context) {
		metrics, err := registryService.GetMetrics()
		if err != nil {
			logger.WithError(err).Error("Failed to get metrics")
			metrics = &pkg.Metrics{
				TotalSystems:   0,
				ActiveSystems:  0,
				TotalServices:  0,
				ActiveServices: 0,
			}
		}

		// Get systems for health calculation
		systems, err := registryService.ListSystems()
		var health map[string]interface{}
		if err != nil {
			logger.WithError(err).Error("Failed to get systems for health")
			health = map[string]interface{}{
				"status":            "unknown",
				"health_percentage": 0,
				"health_ratio":      0.0,
			}
		} else {
			totalSystems := len(systems)
			activeSystems := totalSystems // All registered systems are considered active in Arrowhead 4.x

			var healthPercentage int
			var healthRatio float64
			var status string
			if totalSystems == 0 {
				healthPercentage = 100
				healthRatio = 1.0
				status = "healthy"
			} else {
				healthPercentage = (activeSystems * 100) / totalSystems
				healthRatio = float64(activeSystems) / float64(totalSystems)
				if healthPercentage >= 80 {
					status = "healthy"
				} else if healthPercentage >= 50 {
					status = "degraded"
				} else {
					status = "unhealthy"
				}
			}

			health = map[string]interface{}{
				"status":            status,
				"health_percentage": healthPercentage,
				"health_ratio":      healthRatio,
			}
		}

		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"title":   "Arrowhead IoT Service Mesh",
			"metrics": metrics,
			"health":  health,
		})
	})

	router.GET("/dashboard", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/")
	})

	return router
}

// loadTrustStore loads CA certificates from a PEM file for mTLS verification
func loadTrustStore(truststoreFile string) (*x509.CertPool, error) {
	if truststoreFile == "" {
		return nil, fmt.Errorf("truststore file not specified")
	}

	caCert, err := os.ReadFile(truststoreFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read truststore file: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate from truststore")
	}

	return caCertPool, nil
}
