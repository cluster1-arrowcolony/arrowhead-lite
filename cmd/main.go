package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/api"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

func main() {
	var quiet = flag.Bool("quiet", false, "Disable all logging output")
	var verbose = flag.Bool("verbose", false, "Enable verbose logging")
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

	db, err := internal.NewStorage(cfg.Database.Type, connectionString)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize database")
	}
	defer db.Close()

	registry := internal.NewRegistry(db, logger)

	authManager := internal.NewAuthManager(db, logger, []byte(cfg.Auth.JWTSecret))
	if err := setupAuthKeys(authManager, cfg.Auth); err != nil {
		logger.WithError(err).Warn("Failed to setup auth keys, using JWT secrets only")
	}

	orchestrator := internal.NewOrchestrator(db, logger)
	eventManager := internal.NewEventManager(db, logger)
	healthChecker := internal.NewHealthChecker(registry, logger, cfg.Health.CheckInterval, cfg.Health.InactiveTimeout, cfg.Health.CleanupInterval)

	// Create Gateway components
	relayManager := internal.NewRelayManager(db, cfg, logger)
	gatewaySecurityManager, err := internal.NewGatewaySecurityManager(cfg, logger)
	if err != nil {
		logger.WithError(err).Warn("Failed to initialize gateway security manager")
	}
	gatewayManager := internal.NewGatewayManager(db, cfg, logger, relayManager, gatewaySecurityManager)

	defer eventManager.Close()
	defer healthChecker.Close()
	defer relayManager.Shutdown()
	defer gatewayManager.Shutdown()

	router := setupRouter(cfg, registry, authManager, orchestrator, eventManager, healthChecker, gatewayManager, relayManager, logger)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	if cfg.Server.TLS.Enabled {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
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
func setupAuthKeys(authManager *internal.AuthManager, cfg internal.AuthConfig) error {
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
	registryService *internal.Registry,
	authManager *internal.AuthManager,
	orchestratorService *internal.Orchestrator,
	eventManager *internal.EventManager,
	healthChecker *internal.HealthChecker,
	gatewayManager *internal.GatewayManager,
	relayManager *internal.RelayManager,
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

	h := handlers.New(registryService, authManager, orchestratorService, eventManager, gatewayManager, relayManager, logger)

	router.GET("/health", h.HealthCheck)
	router.GET("/api/v1/health", h.GetDetailedHealth)
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	api := router.Group("/api/v1")

	registry := api.Group("/registry")
	{
		registry.POST("/nodes", h.RegisterNode)
		registry.DELETE("/nodes/:id", h.AuthMiddleware(), h.UnregisterNode)
		registry.GET("/nodes/:id", h.GetNode)
		registry.GET("/nodes", h.ListNodes)

		registry.POST("/services", h.AuthMiddleware(), h.RegisterService)
		registry.DELETE("/services/:id", h.AuthMiddleware(), h.UnregisterService)
		registry.GET("/services/:id", h.GetService)
		registry.GET("/services", h.ListServices)

		registry.POST("/heartbeat", h.AuthMiddleware(), h.UpdateNodeHeartbeat)
	}

	authRoutes := api.Group("/auth")
	{
		authRoutes.POST("/rules", h.AuthMiddleware(), h.CreateAuthRule)
		authRoutes.DELETE("/rules/:id", h.AuthMiddleware(), h.DeleteAuthRule)
		authRoutes.GET("/rules", h.ListAuthRules)
		authRoutes.POST("/token", h.AuthMiddleware(), h.GenerateToken)
		authRoutes.POST("/admin", h.AdminLogin) // Admin login - no auth required
		authRoutes.POST("/login", h.Login)      // Legacy node login - no auth required
	}

	orchestrationRoutes := api.Group("/orchestration")
	{
		orchestrationRoutes.POST("/", h.AuthMiddleware(), h.Orchestrate)
		orchestrationRoutes.GET("/recommendations/:node_id", h.GetServiceRecommendations)
		orchestrationRoutes.GET("/health/:service_id", h.AnalyzeServiceHealth)
	}

	eventsRoutes := api.Group("/events")
	{
		eventsRoutes.POST("/publish", h.AuthMiddleware(), h.PublishEvent)
		eventsRoutes.POST("/subscribe", h.AuthMiddleware(), h.Subscribe)
		eventsRoutes.DELETE("/subscribe/:id", h.AuthMiddleware(), h.Unsubscribe)
		eventsRoutes.GET("/", h.ListEvents)
		eventsRoutes.GET("/subscriptions", h.ListSubscriptions)
	}

	gatewayRoutes := api.Group("/gateway")
	{
		gatewayRoutes.POST("/", h.AuthMiddleware(), h.RegisterGateway)
		gatewayRoutes.GET("/", h.ListGateways)
		gatewayRoutes.GET("/:id", h.GetGateway)

		gatewayRoutes.POST("/:id/tunnels", h.AuthMiddleware(), h.CreateTunnel)
		gatewayRoutes.GET("/:id/tunnels", h.ListTunnels)

		gatewayRoutes.POST("/tunnels/:tunnel_id/sessions", h.AuthMiddleware(), h.CreateGatewaySession)
		gatewayRoutes.DELETE("/sessions/:session_id", h.AuthMiddleware(), h.CloseGatewaySession)
		gatewayRoutes.GET("/sessions/:token/validate", h.ValidateGatewaySession)

		gatewayRoutes.POST("/:id/relay", h.AuthMiddleware(), h.CreateRelayConnection)
		gatewayRoutes.POST("/route", h.AuthMiddleware(), h.RouteGatewayMessage)
		gatewayRoutes.POST("/orchestrate", h.AuthMiddleware(), h.GatewayOrchestrate)
	}

	api.GET("/metrics", h.GetMetrics)

	router.Static("/static", "./web/static")
	router.LoadHTMLGlob("web/templates/*")

	router.GET("/", func(c *gin.Context) {
		metrics, err := registryService.GetMetrics()
		if err != nil {
			logger.WithError(err).Error("Failed to get metrics")
			metrics = &pkg.Metrics{
				TotalNodes:     0,
				ActiveNodes:    0,
				TotalServices:  0,
				ActiveServices: 0,
				TotalEvents:    0,
			}
		}

		// Get nodes for health calculation
		nodes, err := registryService.ListNodes()
		var health map[string]interface{}
		if err != nil {
			logger.WithError(err).Error("Failed to get nodes for health")
			health = map[string]interface{}{
				"status":            "unknown",
				"health_percentage": 0,
				"health_ratio":      0.0,
			}
		} else {
			totalNodes := len(nodes)
			activeNodes := 0
			for _, node := range nodes {
				if node.Status == "online" {
					activeNodes++
				}
			}

			var healthPercentage int
			var healthRatio float64
			var status string
			if totalNodes == 0 {
				healthPercentage = 100
				healthRatio = 1.0
				status = "healthy"
			} else {
				healthPercentage = (activeNodes * 100) / totalNodes
				healthRatio = float64(activeNodes) / float64(totalNodes)
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
