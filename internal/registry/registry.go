package registry

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Database interface for registry storage operations
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
}

type Registry struct {
	db     Database
	logger *logrus.Logger
}

func NewRegistry(db Database, logger *logrus.Logger) *Registry {
	return &Registry{
		db:     db,
		logger: logger,
	}
}

// System Management Methods

// RegisterSystem registers a new system in the registry
func (r *Registry) RegisterSystem(req *pkg.SystemRegistration) (*pkg.System, error) {
	r.logger.WithFields(logrus.Fields{
		"system_name": req.SystemName,
		"address":     req.Address,
		"port":        req.Port,
	}).Info("Registering new system")

	// Check if system already exists
	existing, err := r.db.GetSystemByParams(req.SystemName, req.Address, req.Port)
	if err == nil && existing != nil {
		r.logger.WithField("system_id", existing.ID).Info("System already exists, updating")
		// Update existing system
		existing.AuthenticationInfo = req.AuthenticationInfo
		existing.Metadata = req.Metadata
		now := time.Now()
		existing.UpdatedAt = &now

		if err := r.db.UpdateSystem(existing); err != nil {
			r.logger.WithError(err).Error("Failed to update existing system")
			return nil, pkg.DatabaseError(err)
		}
		return existing, nil
	}

	// Create new system
	now := time.Now()
	system := &pkg.System{
		ID:                 r.generateSystemID(), // Will be overridden by database
		SystemName:         req.SystemName,
		Address:            req.Address,
		Port:               req.Port,
		AuthenticationInfo: req.AuthenticationInfo,
		Metadata:           req.Metadata,
		CreatedAt:          &now,
		UpdatedAt:          &now,
	}

	if err := r.db.CreateSystem(system); err != nil {
		r.logger.WithError(err).Error("Failed to create system")
		return nil, pkg.DatabaseError(err)
	}

	r.logger.WithField("system_id", system.ID).Info("System registered successfully")
	return system, nil
}

// UnregisterSystemByID removes a system by ID
func (r *Registry) UnregisterSystemByID(systemID int) error {
	r.logger.WithField("system_id", systemID).Info("Unregistering system by ID")

	if err := r.db.DeleteSystemByID(systemID); err != nil {
		r.logger.WithError(err).Error("Failed to unregister system")
		return pkg.DatabaseError(err)
	}

	r.logger.WithField("system_id", systemID).Info("System unregistered successfully")
	return nil
}

// UnregisterSystemByParams removes a system by parameters
func (r *Registry) UnregisterSystemByParams(systemName, address string, port int) error {
	r.logger.WithFields(logrus.Fields{
		"system_name": systemName,
		"address":     address,
		"port":        port,
	}).Info("Unregistering system by parameters")

	if err := r.db.DeleteSystemByParams(systemName, address, port); err != nil {
		r.logger.WithError(err).Error("Failed to unregister system")
		return pkg.DatabaseError(err)
	}

	r.logger.Info("System unregistered successfully")
	return nil
}

// GetSystemByID retrieves a system by ID
func (r *Registry) GetSystemByID(systemID int) (*pkg.System, error) {
	system, err := r.db.GetSystemByID(systemID)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get system")
		return nil, pkg.DatabaseError(err)
	}

	if system == nil {
		return nil, pkg.NotFoundError("System not found")
	}

	return system, nil
}

// GetSystemByName retrieves a system by name
func (r *Registry) GetSystemByName(systemName string) (*pkg.System, error) {
	system, err := r.db.GetSystemByName(systemName)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get system by name")
		return nil, pkg.DatabaseError(err)
	}

	if system == nil {
		return nil, pkg.NotFoundError("System not found")
	}

	return system, nil
}

// ListSystems retrieves all systems
func (r *Registry) ListSystems() ([]pkg.System, error) {
	systems, err := r.db.ListSystems("id", "ASC")
	if err != nil {
		r.logger.WithError(err).Error("Failed to list systems")
		return nil, pkg.DatabaseError(err)
	}

	return systems, nil
}

// ListSystemsWithParams retrieves all systems with sorting parameters
func (r *Registry) ListSystemsWithParams(sortField, direction string) ([]pkg.System, error) {
	systems, err := r.db.ListSystems(sortField, direction)
	if err != nil {
		r.logger.WithError(err).Error("Failed to list systems")
		return nil, pkg.DatabaseError(err)
	}

	r.logger.WithFields(logrus.Fields{
		"sort_field": sortField,
		"direction":  direction,
	}).Debug("Listed systems with parameters")

	return systems, nil
}

// Service Management Methods

// RegisterServiceMgmt registers a service via management API
func (r *Registry) RegisterServiceMgmt(req *pkg.ServiceRegistrationRequest) (*pkg.Service, error) {
	return r.registerService(req, true)
}

// RegisterService registers a service via public API
func (r *Registry) RegisterService(req *pkg.ServiceRegistrationRequest) (*pkg.Service, error) {
	return r.registerService(req, false)
}

// registerService handles the common service registration logic
func (r *Registry) registerService(req *pkg.ServiceRegistrationRequest, isManagement bool) (*pkg.Service, error) {
	r.logger.WithFields(logrus.Fields{
		"service_definition": req.ServiceDefinition,
		"provider_system":    req.ProviderSystem.SystemName,
		"service_uri":        req.ServiceUri,
		"management":         isManagement,
	}).Info("Registering new service")

	// Get or create provider system
	provider, err := r.getOrCreateProvider(&req.ProviderSystem)
	if err != nil {
		return nil, err
	}

	// Get or create service definition
	serviceDef, err := r.getOrCreateServiceDefinition(req.ServiceDefinition)
	if err != nil {
		return nil, err
	}

	// Get or create interfaces
	interfaces, err := r.getOrCreateInterfaces(req.Interfaces)
	if err != nil {
		return nil, err
	}

	// Parse version
	version := 1
	if req.Version != "" {
		if v, err := strconv.Atoi(req.Version); err == nil {
			version = v
		}
	}

	// Create service
	now := time.Now()
	var endOfValidity *time.Time
	if req.EndOfValidity != "" {
		if t, err := time.Parse(time.RFC3339, req.EndOfValidity); err == nil {
			endOfValidity = &t
		}
	}

	service := &pkg.Service{
		ID:                r.generateServiceID(), // Will be overridden by database
		ServiceDefinition: *serviceDef,
		Provider:          *provider,
		ServiceUri:        req.ServiceUri,
		EndOfValidity:     endOfValidity,
		Secure:            req.Secure,
		Metadata:          req.Metadata,
		Version:           version,
		Interfaces:        interfaces,
		CreatedAt:         &now,
		UpdatedAt:         &now,
	}

	if err := r.db.CreateService(service); err != nil {
		r.logger.WithError(err).Error("Failed to create service")
		return nil, pkg.DatabaseError(err)
	}

	r.logger.WithField("service_id", service.ID).Info("Service registered successfully")
	return service, nil
}

// UnregisterServiceByID removes a service by ID
func (r *Registry) UnregisterServiceByID(serviceID int) error {
	r.logger.WithField("service_id", serviceID).Info("Unregistering service by ID")

	if err := r.db.DeleteServiceByID(serviceID); err != nil {
		r.logger.WithError(err).Error("Failed to unregister service")
		return pkg.DatabaseError(err)
	}

	r.logger.WithField("service_id", serviceID).Info("Service unregistered successfully")
	return nil
}

// UnregisterServiceByParams removes a service by parameters
func (r *Registry) UnregisterServiceByParams(systemName, serviceURI, serviceDefinition, address string, port int) error {
	r.logger.WithFields(logrus.Fields{
		"system_name":        systemName,
		"service_uri":        serviceURI,
		"service_definition": serviceDefinition,
		"address":            address,
		"port":               port,
	}).Info("Unregistering service by parameters")

	if err := r.db.DeleteServiceByParams(systemName, serviceURI, serviceDefinition, address, port); err != nil {
		r.logger.WithError(err).Error("Failed to unregister service")
		return pkg.DatabaseError(err)
	}

	r.logger.Info("Service unregistered successfully")
	return nil
}

// GetServiceByID retrieves a service by ID
func (r *Registry) GetServiceByID(serviceID int) (*pkg.Service, error) {
	service, err := r.db.GetServiceByID(serviceID)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get service")
		return nil, pkg.DatabaseError(err)
	}

	if service == nil {
		return nil, pkg.NotFoundError("Service not found")
	}

	return service, nil
}

// ListServices retrieves all services
func (r *Registry) ListServices() ([]pkg.Service, error) {
	services, err := r.db.ListServices("id", "ASC")
	if err != nil {
		r.logger.WithError(err).Error("Failed to list services")
		return nil, pkg.DatabaseError(err)
	}

	return services, nil
}

// ListServicesWithParams retrieves all services with sorting parameters
func (r *Registry) ListServicesWithParams(sortField, direction string) ([]pkg.Service, error) {
	services, err := r.db.ListServices(sortField, direction)
	if err != nil {
		r.logger.WithError(err).Error("Failed to list services")
		return nil, pkg.DatabaseError(err)
	}

	r.logger.WithFields(logrus.Fields{
		"sort_field": sortField,
		"direction":  direction,
	}).Debug("Listed services with parameters")

	return services, nil
}

// Authorization Management Methods

// AddAuthorization creates a new authorization rule
func (r *Registry) AddAuthorization(req *pkg.AddAuthorizationRequest) (*pkg.Authorization, error) {
	r.logger.WithFields(logrus.Fields{
		"consumer_id":            req.ConsumerID,
		"provider_ids":           req.ProviderIDs,
		"service_definition_ids": req.ServiceDefinitionIDs,
		"interface_ids":          req.InterfaceIDs,
	}).Info("Adding authorization rule")

	// Get consumer system
	consumer, err := r.db.GetSystemByID(req.ConsumerID)
	if err != nil || consumer == nil {
		return nil, pkg.NotFoundError("Consumer system not found")
	}

	// For simplicity, create authorization for the first provider and service definition
	if len(req.ProviderIDs) == 0 || len(req.ServiceDefinitionIDs) == 0 {
		return nil, pkg.BadRequestError("Provider IDs and Service Definition IDs are required")
	}

	providerID := req.ProviderIDs[0]
	serviceDefID := req.ServiceDefinitionIDs[0]

	// Get provider system
	provider, err := r.db.GetSystemByID(providerID)
	if err != nil || provider == nil {
		return nil, pkg.NotFoundError("Provider system not found")
	}

	// Get service definition
	serviceDef, err := r.db.GetServiceDefinitionByID(serviceDefID)
	if err != nil || serviceDef == nil {
		return nil, pkg.NotFoundError("Service definition not found")
	}

	// Get interfaces
	interfaces := make([]pkg.Interface, 0)
	for _, interfaceID := range req.InterfaceIDs {
		iface, err := r.db.GetInterfaceByID(interfaceID)
		if err == nil && iface != nil {
			interfaces = append(interfaces, *iface)
		}
	}

	// Convert System to Provider for authorization
	providerForAuth := pkg.Provider{
		ID:                 provider.ID,
		SystemName:         provider.SystemName,
		Address:            provider.Address,
		Port:               provider.Port,
		AuthenticationInfo: provider.AuthenticationInfo,
		Metadata:           provider.Metadata,
		CreatedAt:          provider.CreatedAt,
		UpdatedAt:          provider.UpdatedAt,
	}

	// Create authorization
	now := time.Now()
	authorization := &pkg.Authorization{
		ID:                r.generateAuthID(), // Will be overridden by database
		ConsumerSystem:    *consumer,
		ProviderSystem:    providerForAuth,
		ServiceDefinition: *serviceDef,
		Interfaces:        interfaces,
		CreatedAt:         &now,
		UpdatedAt:         &now,
	}

	if err := r.db.CreateAuthorization(authorization); err != nil {
		r.logger.WithError(err).Error("Failed to create authorization")
		return nil, pkg.DatabaseError(err)
	}

	r.logger.WithField("auth_id", authorization.ID).Info("Authorization created successfully")
	return authorization, nil
}

// RemoveAuthorization removes an authorization rule by ID
func (r *Registry) RemoveAuthorization(authID int) error {
	r.logger.WithField("auth_id", authID).Info("Removing authorization")

	if err := r.db.DeleteAuthorizationByID(authID); err != nil {
		r.logger.WithError(err).Error("Failed to remove authorization")
		return pkg.DatabaseError(err)
	}

	r.logger.WithField("auth_id", authID).Info("Authorization removed successfully")
	return nil
}

// ListAuthorizations retrieves all authorization rules
func (r *Registry) ListAuthorizations() ([]pkg.Authorization, error) {
	authorizations, err := r.db.ListAuthorizations("id", "ASC")
	if err != nil {
		r.logger.WithError(err).Error("Failed to list authorizations")
		return nil, pkg.DatabaseError(err)
	}

	return authorizations, nil
}

// ListAuthorizationsWithParams retrieves all authorization rules with sorting parameters
func (r *Registry) ListAuthorizationsWithParams(sortField, direction string) ([]pkg.Authorization, error) {
	authorizations, err := r.db.ListAuthorizations(sortField, direction)
	if err != nil {
		r.logger.WithError(err).Error("Failed to list authorizations")
		return nil, pkg.DatabaseError(err)
	}

	r.logger.WithFields(logrus.Fields{
		"sort_field": sortField,
		"direction":  direction,
	}).Debug("Listed authorizations with parameters")

	return authorizations, nil
}

// Helper Methods

// getOrCreateProvider gets an existing provider or creates a new one
func (r *Registry) getOrCreateProvider(providerSystem *pkg.ProviderSystem) (*pkg.Provider, error) {
	// Try to find existing system
	system, err := r.db.GetSystemByParams(providerSystem.SystemName, providerSystem.Address, providerSystem.Port)
	if err == nil && system != nil {
		// Convert System to Provider
		return &pkg.Provider{
			ID:                 system.ID,
			SystemName:         system.SystemName,
			Address:            system.Address,
			Port:               system.Port,
			AuthenticationInfo: system.AuthenticationInfo,
			Metadata:           system.Metadata,
			CreatedAt:          system.CreatedAt,
			UpdatedAt:          system.UpdatedAt,
		}, nil
	}

	// Create new system
	now := time.Now()
	newSystem := &pkg.System{
		ID:                 r.generateSystemID(),
		SystemName:         providerSystem.SystemName,
		Address:            providerSystem.Address,
		Port:               providerSystem.Port,
		AuthenticationInfo: providerSystem.AuthenticationInfo,
		Metadata:           providerSystem.Metadata,
		CreatedAt:          &now,
		UpdatedAt:          &now,
	}

	if err := r.db.CreateSystem(newSystem); err != nil {
		return nil, fmt.Errorf("failed to create provider system: %w", err)
	}

	// Convert to Provider
	return &pkg.Provider{
		ID:                 newSystem.ID,
		SystemName:         newSystem.SystemName,
		Address:            newSystem.Address,
		Port:               newSystem.Port,
		AuthenticationInfo: newSystem.AuthenticationInfo,
		Metadata:           newSystem.Metadata,
		CreatedAt:          newSystem.CreatedAt,
		UpdatedAt:          newSystem.UpdatedAt,
	}, nil
}

// getOrCreateServiceDefinition gets an existing service definition or creates a new one
func (r *Registry) getOrCreateServiceDefinition(serviceDefinition string) (*pkg.ServiceDefinition, error) {
	// Try to find existing service definition
	existing, err := r.db.GetServiceDefinitionByName(serviceDefinition)
	if err == nil && existing != nil {
		return existing, nil
	}

	// Create new service definition
	now := time.Now()
	serviceDef := &pkg.ServiceDefinition{
		ID:                r.generateServiceDefID(),
		ServiceDefinition: serviceDefinition,
		CreatedAt:         &now,
		UpdatedAt:         &now,
	}

	if err := r.db.CreateServiceDefinition(serviceDef); err != nil {
		return nil, fmt.Errorf("failed to create service definition: %w", err)
	}

	return serviceDef, nil
}

// getOrCreateInterfaces gets existing interfaces or creates new ones
func (r *Registry) getOrCreateInterfaces(interfaceNames []string) ([]pkg.Interface, error) {
	interfaces := make([]pkg.Interface, 0, len(interfaceNames))

	for _, interfaceName := range interfaceNames {
		// Try to find existing interface
		existing, err := r.db.GetInterfaceByName(interfaceName)
		if err == nil && existing != nil {
			interfaces = append(interfaces, *existing)
			continue
		}

		// Create new interface
		now := time.Now()
		iface := &pkg.Interface{
			ID:            r.generateInterfaceID(),
			InterfaceName: interfaceName,
			CreatedAt:     &now,
			UpdatedAt:     &now,
		}

		if err := r.db.CreateInterface(iface); err != nil {
			r.logger.WithError(err).WithField("interface", interfaceName).Warn("Failed to create interface")
			continue
		}

		interfaces = append(interfaces, *iface)
	}

	return interfaces, nil
}

// ID generation methods (these would be replaced by database auto-increment)
func (r *Registry) generateSystemID() int {
	return r.generateRandomID()
}

func (r *Registry) generateServiceID() int {
	return r.generateRandomID()
}

func (r *Registry) generateServiceDefID() int {
	return r.generateRandomID()
}

func (r *Registry) generateInterfaceID() int {
	return r.generateRandomID()
}

func (r *Registry) generateAuthID() int {
	return r.generateRandomID()
}

func (r *Registry) generateRandomID() int {
	// Generate a random ID (in real implementation, this would be handled by database auto-increment)
	randomBytes := make([]byte, 4)
	_, _ = rand.Read(randomBytes)
	id := int(randomBytes[0])<<24 | int(randomBytes[1])<<16 | int(randomBytes[2])<<8 | int(randomBytes[3])
	if id < 0 {
		id = -id
	}
	if id == 0 {
		id = 1
	}
	return id
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
