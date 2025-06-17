package auth

import (
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Database interface for auth storage operations (moved from manager.go)
type Database interface {
	GetSystemByID(id int) (*pkg.System, error)
	GetServiceByID(id int) (*pkg.Service, error)
	GetAuthorizationByID(id int) (*pkg.Authorization, error)
	GetAuthorizationsByConsumer(consumerID int) ([]pkg.Authorization, error)
	GetAuthorizationsByProvider(providerID int) ([]pkg.Authorization, error)
	CreateAuthorization(auth *pkg.Authorization) error
	DeleteAuthorizationByID(id int) error
	ListAuthorizations(sortField, direction string) ([]pkg.Authorization, error)
	CheckAuthorization(consumerID, providerID, serviceDefinitionID int, interfaceIDs []int) (bool, error)
}

// NewAuthManager creates a new auth manager instance
func NewAuthManager(db Database, logger *logrus.Logger, jwtSecret []byte) *AuthManager {
	return newAuthManager(db, logger, jwtSecret)
}
