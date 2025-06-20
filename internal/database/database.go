package database

import (
	"fmt"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
)

type Database interface {
	// System operations (Arrowhead 4.x)
	CreateSystem(system *pkg.System) error
	GetSystemByID(id int) (*pkg.System, error)
	GetSystemByName(systemName string) (*pkg.System, error)
	GetSystemByParams(systemName, address string, port int) (*pkg.System, error)
	UpdateSystem(system *pkg.System) error
	DeleteSystemByID(id int) error
	DeleteSystemByParams(systemName, address string, port int) error
	ListSystems(sortField, direction string) ([]pkg.System, error)

	// Service operations (Arrowhead 4.x)
	CreateService(service *pkg.Service) error
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

	// Authorization operations (Arrowhead 4.x)
	CreateAuthorization(auth *pkg.Authorization) error
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

// NewStorage creates database storage based on configuration
func NewStorage(dbType string, connection string) (Database, error) {
	switch dbType {
	case "postgres", "postgresql":
		return NewPostgreSQL(connection)
	case "sqlite", "sqlite3":
		return NewSQLiteDB(connection)
	default:
		return nil, fmt.Errorf("unsupported database type: %s (supported: postgres, sqlite)", dbType)
	}
}
