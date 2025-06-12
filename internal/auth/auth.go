package auth

import (
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Database interface for auth storage operations (moved from manager.go)
type Database interface {
	GetNode(id string) (*pkg.Node, error)
	GetService(id string) (*pkg.Service, error)
	GetAuthRule(id string) (*pkg.AuthRule, error)
	GetAuthRules(consumerID, providerID, serviceID string) ([]*pkg.AuthRule, error)
	CreateAuthRule(rule *pkg.AuthRule) error
	DeleteAuthRule(id string) error
	ListAuthRules() ([]*pkg.AuthRule, error)
}

// NewAuthManager creates a new auth manager instance
func NewAuthManager(db Database, logger *logrus.Logger, jwtSecret []byte) *AuthManager {
	return newAuthManager(db, logger, jwtSecret)
}
