package health

import (
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Registry interface for health monitoring operations (moved from monitor.go)
type Registry interface {
	ListServices() ([]*pkg.Service, error)
	ListNodes() ([]*pkg.Node, error)
	ListServicesByNode(nodeID string) ([]*pkg.Service, error)
	GetNode(nodeID string) (*pkg.Node, error)
	UpdateServiceHealth(serviceID string, status pkg.ServiceStatus) error
	CleanupInactiveNodes(inactiveTimeout time.Duration) error
	GetMetrics() (*pkg.Metrics, error)
}

// NewHealthChecker creates a new health checker instance
func NewHealthChecker(registry Registry, logger *logrus.Logger, checkInterval, inactiveTimeout, cleanupInterval time.Duration) *HealthChecker {
	return newHealthChecker(registry, logger, checkInterval, inactiveTimeout, cleanupInterval)
}
