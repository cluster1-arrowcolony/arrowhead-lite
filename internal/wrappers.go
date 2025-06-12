package internal

import (
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/auth"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/database"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/events"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/gateway"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/health"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/orchestration"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/registry"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/relay"
	"github.com/sirupsen/logrus"
)

// Re-export types for backward compatibility
type Registry = registry.Registry
type AuthManager = auth.AuthManager
type Claims = auth.Claims
type Orchestrator = orchestration.Orchestrator
type ServiceCandidate = orchestration.ServiceCandidate
type EventManager = events.EventManager
type Subscriber = events.Subscriber
type HealthChecker = health.HealthChecker
type GatewayManager = gateway.GatewayManager
type GatewaySecurityManager = gateway.GatewaySecurityManager
type TrustAnchor = gateway.TrustAnchor
type CertificateValidationResult = gateway.CertificateValidationResult
type RelayManager = relay.RelayManager
type RelayClient = relay.RelayClient
type MessageDelivery = relay.MessageDelivery
type Database = database.Database

// Wrapper functions for backward compatibility
func NewRegistry(db database.Database, logger *logrus.Logger) *Registry {
	return registry.NewRegistry(db, logger)
}

func NewAuthManager(db database.Database, logger *logrus.Logger, jwtSecret []byte) *AuthManager {
	return auth.NewAuthManager(db, logger, jwtSecret)
}

func NewOrchestrator(db database.Database, logger *logrus.Logger) *Orchestrator {
	return orchestration.NewOrchestrator(db, logger)
}

func NewEventManager(db database.Database, logger *logrus.Logger) *EventManager {
	return events.NewEventManager(db, logger)
}

func NewHealthChecker(registry *Registry, logger *logrus.Logger, checkInterval, inactiveTimeout, cleanupInterval time.Duration) *HealthChecker {
	return health.NewHealthChecker(registry, logger, checkInterval, inactiveTimeout, cleanupInterval)
}

func NewGatewayManager(db database.Database, config *Config, logger *logrus.Logger, relayManager *RelayManager, securityLayer *GatewaySecurityManager) *GatewayManager {
	return gateway.NewGatewayManager(db, config, logger, relayManager, securityLayer)
}

func NewGatewaySecurityManager(config *Config, logger *logrus.Logger) (*GatewaySecurityManager, error) {
	return gateway.NewGatewaySecurityManager(config, logger)
}

func NewRelayManager(db database.Database, config *Config, logger *logrus.Logger) *RelayManager {
	return relay.NewRelayManager(db, config, logger)
}

func NewStorage(dbType string, connection string) (database.Database, error) {
	return database.NewStorage(dbType, connection)
}
