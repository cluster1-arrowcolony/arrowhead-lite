package registry

import (
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Database interface for registry storage operations
type Database interface {
	// Node operations
	CreateNode(Node *pkg.Node) error
	GetNode(id string) (*pkg.Node, error)
	GetNodeByName(name string) (*pkg.Node, error)
	UpdateNode(Node *pkg.Node) error
	DeleteNode(id string) error
	ListNodes() ([]*pkg.Node, error)

	// Service operations
	CreateService(service *pkg.Service) error
	GetService(id string) (*pkg.Service, error)
	GetServicesByNode(nodeID string) ([]*pkg.Service, error)
	GetServicesByName(name string) ([]*pkg.Service, error)
	UpdateService(service *pkg.Service) error
	DeleteService(id string) error
	ListServices() ([]*pkg.Service, error)

	// Metrics
	GetMetrics() (*pkg.Metrics, error)
}

type Registry struct {
	db     Database
	logger *logrus.Logger
}

func NewRegistry(db Database, logger *logrus.Logger) *Registry {
	return newRegistry(db, logger)
}

func newRegistry(db Database, logger *logrus.Logger) *Registry {
	return &Registry{
		db:     db,
		logger: logger,
	}
}

// GetMetrics returns registry metrics
func (r *Registry) GetMetrics() (*pkg.Metrics, error) {
	metrics, err := r.db.GetMetrics()
	if err != nil {
		r.logger.WithError(err).Error("Failed to get metrics")
		return nil, pkg.DatabaseError(err)
	}

	return metrics, nil
}
