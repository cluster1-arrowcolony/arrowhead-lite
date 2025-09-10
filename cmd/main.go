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
	"strings"
	"syscall"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/api"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/auth"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/database"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/orchestration"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/registry"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

type CoreSystems struct {
	registry     *registry.Registry
	authManager  *auth.AuthManager
	orchestrator *orchestration.Orchestrator
}

func main() {
	cfg, logger := readConfig()
	logger.Info("Starting Arrowhead IoT Service Mesh")
	db := createDatabase(cfg.Database, logger)
	defer func() {
		if err := db.Close(); err != nil {
			logger.WithError(err).Error("Failed to close database")
		}
	}()
	coreSystems := createCoreSystems(db, cfg, logger)
	httpServer := createHTTPServer(cfg, coreSystems, logger)
	runAndShutdownServer(httpServer, cfg, logger)
	logger.Info("Server exited")
}

func createLogger(cfg internal.LoggingConfig) *logrus.Logger {
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
		file, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			logger.WithError(err).Warn("Failed to open log file, using stdout")
		} else {
			logger.SetOutput(file)
		}
	}
	return logger
}

func readConfig() (*internal.Config, *logrus.Logger) {
	var quiet = flag.Bool("quiet", false, "Disable all logging output")
	var verbose = flag.Bool("verbose", false, "Enable verbose logging")
	var clean = flag.Bool("clean", false, "Run with a clean database")
	flag.Parse()

	configPath := os.Getenv("ARROWHEAD_CONFIG")
	cfg, err := internal.LoadConfig(configPath)

	logger := createLogger(cfg.Logging)

	if *clean {
		dbPath := "./arrowhead.db"
		if _, err := os.Stat(dbPath); err == nil {
			if err := os.Remove(dbPath); err != nil {
				logger.WithError(err).Fatalf("Failed to remove database file: %s", dbPath)
			}
			logger.Printf("Removed database file: %s\n", dbPath)
		} else {
			logger.Println("Database file not found, nothing to clean.")
		}
	}

	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}

	if *quiet {
		cfg.Logging.Level = "panic"
	} else if *verbose {
		cfg.Logging.Level = "debug"
	}

	return cfg, logger
}

func createDatabase(cfg internal.DatabaseConfig, logger *logrus.Logger) database.Database {
	var db database.Database
	var err error
	switch cfg.Type {
	case "postgresql":
		var conn = fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Name)
		db, err = database.NewPostgreSQLDB(conn)
	case "sqlite":
		var conn = cfg.Path
		if conn == "" {
			conn = "./arrowhead.db"
		}
		db, err = database.NewSQLiteDB(conn)
	default:
		err = fmt.Errorf("unsupported database type: %s (supported: postgresql, sqlite)", cfg.Type)
	}
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize database")
	}
	return db
}

func createCoreSystems(db database.Database, cfg *internal.Config, logger *logrus.Logger) *CoreSystems {
	authMgr := auth.NewAuthManager(db, logger, []byte(cfg.Auth.JWTSecret))
	if err := setupAuthKeys(authMgr, cfg.Auth); err != nil {
		logger.WithError(err).Warn("Failed to setup auth keys, using JWT secrets only")
	}
	return &CoreSystems{
		registry:     registry.NewRegistry(db, logger),
		authManager:  authMgr,
		orchestrator: orchestration.NewOrchestrator(db, authMgr, logger),
	}
}

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

func createHTTPServer(cfg *internal.Config, coreSystems *CoreSystems, logger *logrus.Logger) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      createGinRouter(cfg, coreSystems, logger),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  loadTrustStore(cfg.Server.TLS.TruststoreFile, logger),
		},
	}
}

func runAndShutdownServer(server *http.Server, cfg *internal.Config, logger *logrus.Logger) {
	go func() {
		logger.WithFields(logrus.Fields{
			"address": server.Addr,
			"tls":     true,
		}).Info("Starting HTTPS server")
		err := server.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Fatal("Server forced to shutdown")
	}
}

func createGinRouter(
	cfg *internal.Config,
	coreSystems *CoreSystems,
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

	h := handlers.NewHandlers(coreSystems.registry, coreSystems.authManager, coreSystems.orchestrator, logger)

	router.GET("/health", h.HealthCheck)
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	serviceRegistry := router.Group("/serviceregistry")
	{
		mgmt := serviceRegistry.Group("/mgmt")
		{
			systems := mgmt.Group("/systems")
			{
				systems.GET("", h.ListSystems)
				systems.GET("/:id", h.GetSystemByID)
				systems.POST("", h.AuthMiddleware(), h.RegisterSystem)
				systems.POST("/batch", h.AuthMiddleware(), h.RegisterSystemsBatch)
				systems.DELETE("/:id", h.AuthMiddleware(), h.UnregisterSystemByID)
			}
			services := mgmt.Group("/services")
			{
				services.GET("", h.ListServices)
				services.GET("/:id", h.GetServiceByID)
				services.POST("", h.AuthMiddleware(), h.RegisterServiceMgmt)
				services.POST("/batch", h.AuthMiddleware(), h.RegisterServicesBatch)
				services.DELETE("/:id", h.AuthMiddleware(), h.UnregisterServiceByID)
			}
		}
		serviceRegistry.POST("/register-system", h.RegisterSystemPublic)
		serviceRegistry.DELETE("/unregister-system", h.UnregisterSystemPublic)
		serviceRegistry.POST("/register", h.AuthMiddleware(), h.RegisterService)
		serviceRegistry.DELETE("/unregister", h.AuthMiddleware(), h.UnregisterService)
	}
	authorization := router.Group("/authorization")
	{
		authMgmt := authorization.Group("/mgmt")
		{
			authMgmt.POST("/intracloud", h.AuthMiddleware(), h.AddAuthorization)
			authMgmt.POST("/intracloud/batch", h.AuthMiddleware(), h.AddAuthorizationsBatch)
			authMgmt.DELETE("/intracloud/:id", h.AuthMiddleware(), h.RemoveAuthorization)
			authMgmt.GET("/intracloud", h.ListAuthorizations)
		}
	}
	orchestrator := router.Group("/orchestrator")
	{
		orchestrator.POST("/orchestration", h.AuthMiddleware(), h.Orchestrate)
	}
	router.Static("/static", "./web/static")
	router.LoadHTMLGlob("web/templates/*")
	router.GET("/", func(c *gin.Context) {
		metrics, err := coreSystems.registry.GetMetrics()
		if err != nil {
			logger.WithError(err).Error("Failed to get metrics")
			metrics = &pkg.Metrics{
				TotalSystems:   0,
				ActiveSystems:  0,
				TotalServices:  0,
				ActiveServices: 0,
			}
		}
		systems, err := coreSystems.registry.ListSystems()
		var health map[string]any
		if err != nil {
			logger.WithError(err).Error("Failed to get systems for health")
			health = map[string]any{
				"status":            "unknown",
				"health_percentage": 0,
				"health_ratio":      0.0,
			}
		} else {
			var healthPercentage int
			var healthRatio float64
			var status string
			if len(systems) == 0 {
				healthPercentage = 100
				healthRatio = 1.0
				status = "healthy"
			} else {
				healthPercentage = (len(systems) * 100) / len(systems)
				healthRatio = float64(len(systems)) / float64(len(systems))
				if healthPercentage >= 80 {
					status = "healthy"
				} else if healthPercentage >= 50 {
					status = "degraded"
				} else {
					status = "unhealthy"
				}
			}

			health = map[string]any{
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

func loadTrustStore(truststoreFile string, logger *logrus.Logger) *x509.CertPool {
	if truststoreFile == "" {
		logger.Fatal("truststore file not specified")
		return nil
	}

	if strings.Contains(truststoreFile, "..") {
		logger.Error("invalid truststore file path")
		return nil
	}

	caCert, err := os.ReadFile(truststoreFile) // #nosec G304
	if err != nil {
		logger.WithError(err).Fatalf("failed to read truststore file: %s", truststoreFile)
		return nil
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		logger.Error("failed to parse CA certificate from truststore")
		return nil
	}

	return caCertPool
}
