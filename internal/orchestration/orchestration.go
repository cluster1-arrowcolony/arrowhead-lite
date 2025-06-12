package orchestration

import (
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Database interface for orchestration storage operations (moved from orchestrator.go)
type Database interface {
	GetNode(id string) (*pkg.Node, error)
	GetNodeByName(name string) (*pkg.Node, error)
	GetService(id string) (*pkg.Service, error)
	GetServicesByName(name string) ([]*pkg.Service, error)
	GetServicesByNode(nodeID string) ([]*pkg.Service, error)
	ListServices() ([]*pkg.Service, error)
}

// NewOrchestrator creates a new orchestrator instance
func NewOrchestrator(db Database, logger *logrus.Logger) *Orchestrator {
	return newOrchestrator(db, logger)
}
