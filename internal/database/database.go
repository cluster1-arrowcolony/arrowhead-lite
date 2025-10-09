// Package database provides a storage abstraction layer for Arrowhead core services.
//
// This package defines the Database interface that abstracts persistence operations
// for systems, services, authorizations, and related entities. It supports multiple
// database backends (SQLite, PostgreSQL) through a common interface.
//
// Implementations must be safe for concurrent use and support atomic transactions
// for batch operations.
package database

import (
	"fmt"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
)

// Database provides persistent storage for Arrowhead core system data.
//
// All implementations must be safe for concurrent use by multiple goroutines
// and support atomic batch operations. Methods return pkg.AppError types for
// consistent error handling across the application.
type Database interface {
	// System operations

	// CreateSystem persists a new system registration.
	// Returns an error if a system with the same name/address/port already exists.
	// The system's ID field will be populated with the database-assigned identifier.
	CreateSystem(system *pkg.System) error

	// CreateSystemsBatch atomically creates multiple systems in a single transaction.
	// All systems succeed together or all fail together.
	// System IDs are populated on success.
	CreateSystemsBatch(systems []*pkg.System) error

	// GetSystemByID retrieves a system by its database ID.
	// Returns nil with no error if the system is not found.
	GetSystemByID(id int) (*pkg.System, error)

	// GetSystemByName retrieves a system by its unique name.
	// Returns nil with no error if the system is not found.
	GetSystemByName(systemName string) (*pkg.System, error)

	// GetSystemByParams retrieves a system by its network parameters.
	// Returns nil with no error if no matching system exists.
	GetSystemByParams(systemName, address string, port int) (*pkg.System, error)

	// UpdateSystem updates an existing system's fields.
	// Returns an error if the system does not exist.
	UpdateSystem(system *pkg.System) error

	// DeleteSystemByID removes a system and all its associated services.
	// Returns an error if the system does not exist.
	DeleteSystemByID(id int) error

	// DeleteSystemByParams removes a system identified by network parameters.
	// Returns an error if the system does not exist.
	DeleteSystemByParams(systemName, address string, port int) error

	// ListSystems retrieves all registered systems with optional sorting.
	// sortField can be "id", "system_name", "created_at", etc.
	// direction must be "ASC" or "DESC".
	ListSystems(sortField, direction string) ([]pkg.System, error)

	// Service operations
	CreateService(service *pkg.Service) error
	CreateServicesBatch(services []*pkg.Service) error
	GetServiceByID(id int) (*pkg.Service, error)
	GetServicesByProvider(providerID int) ([]pkg.Service, error)
	GetServicesByDefinition(serviceDefinition string) ([]pkg.Service, error)
	UpdateService(service *pkg.Service) error
	DeleteServiceByID(id int) error
	DeleteServiceByParams(systemName, serviceURI, serviceDefinition, address string, port int) error
	ListServices(sortField, direction string) ([]pkg.Service, error)

	// Service Definition operations
	CreateServiceDefinition(serviceDef *pkg.ServiceDefinition) error
	GetServiceDefinitionByID(id int) (*pkg.ServiceDefinition, error)
	GetServiceDefinitionByName(name string) (*pkg.ServiceDefinition, error)
	ListServiceDefinitions() ([]pkg.ServiceDefinition, error)

	// Interface operations
	CreateInterface(iface *pkg.Interface) error
	GetInterfaceByID(id int) (*pkg.Interface, error)
	GetInterfaceByName(name string) (*pkg.Interface, error)
	ListInterfaces() ([]pkg.Interface, error)

	// Authorization operations
	CreateAuthorization(auth *pkg.Authorization) error
	CreateAuthorizationsBatch(auths []*pkg.Authorization) error
	GetAuthorizationByID(id int) (*pkg.Authorization, error)
	GetAuthorizationsByConsumer(consumerID int) ([]pkg.Authorization, error)
	GetAuthorizationsByProvider(providerID int) ([]pkg.Authorization, error)
	DeleteAuthorizationByID(id int) error
	ListAuthorizations(sortField, direction string) ([]pkg.Authorization, error)
	CheckAuthorization(consumerID, providerID, serviceDefinitionID int, interfaceIDs []int) (bool, error)

	// Metrics
	GetMetrics() (*pkg.Metrics, error)

	Close() error
}

// NewDatabase creates database storage based on configuration
func NewDatabase(dbType string, connection string) (Database, error) {
	switch dbType {
	case "postgresql":
		return NewPostgreSQLDB(connection)
	case "sqlite":
		return NewSQLiteDB(connection)
	default:
		return nil, fmt.Errorf("unsupported database type: %s (supported: postgres, sqlite)", dbType)
	}
}
