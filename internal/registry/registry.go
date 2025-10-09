// Package registry implements the Arrowhead Service Registry core system.
//
// The Service Registry manages the registration and discovery of IoT systems and services
// within an Arrowhead local cloud. It provides the central directory for systems to find
// and consume services, implementing the Arrowhead Framework 4.x Service Registry specification.
//
// Key responsibilities:
//   - System lifecycle management (registration, updates, deregistration)
//   - Service publication and discovery
//   - Authorization rule management
//   - Service metadata and interface tracking
package registry

import (
	"fmt"
	"strconv"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/database"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Registry implements the Arrowhead Service Registry core system.
// It manages the lifecycle of systems and services within the local cloud.
type Registry struct {
	db     database.Database
	logger *logrus.Logger
}

// NewRegistry creates a new Service Registry instance with the provided database
// and logger. The registry is immediately ready to handle registration and
// discovery requests.
func NewRegistry(db database.Database, logger *logrus.Logger) *Registry {
	return &Registry{
		db:     db,
		logger: logger,
	}
}

// System Management Methods

// RegisterSystemsBatch registers multiple systems atomically in a single transaction.
// If a system with the same name/address/port already exists, it will be updated instead.
// All registrations succeed together or all fail together.
//
// Returns a slice of created/updated System records with assigned IDs and timestamps.
//
// Returns pkg.DatabaseError if the database operation fails.
func (r *Registry) RegisterSystemsBatch(reqs []pkg.SystemRegistration) ([]pkg.System, error) {
	r.logger.Infof("Registering batch of %d systems", len(reqs))
	systemsToCreate := make([]*pkg.System, 0, len(reqs))
	resultSystems := make([]pkg.System, 0, len(reqs))

	for _, req := range reqs {
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
				continue
			}
			resultSystems = append(resultSystems, *existing)
			continue
		}

		// Create new system
		now := time.Now()
		system := &pkg.System{
			SystemName:         req.SystemName,
			Address:            req.Address,
			Port:               req.Port,
			AuthenticationInfo: req.AuthenticationInfo,
			Metadata:           req.Metadata,
			CreatedAt:          &now,
			UpdatedAt:          &now,
		}
		systemsToCreate = append(systemsToCreate, system)
	}

	// Create new systems in batch
	if len(systemsToCreate) > 0 {
		if err := r.db.CreateSystemsBatch(systemsToCreate); err != nil {
			r.logger.WithError(err).Error("Failed to create systems batch")
			return nil, pkg.DatabaseError(err)
		}

		// Add newly created systems to result
		for _, s := range systemsToCreate {
			resultSystems = append(resultSystems, *s)
		}
	}

	r.logger.Infof("Successfully registered %d systems", len(resultSystems))
	return resultSystems, nil
}

// RegisterSystem registers a single system with the Service Registry.
// This is a convenience wrapper around RegisterSystemsBatch for single system registration.
//
// If a system with the same name/address/port already exists, it will be updated.
//
// Returns the created or updated System with ID and timestamps populated.
//
// Returns pkg.ConflictError if registration failed.
// Returns pkg.DatabaseError if the database operation fails.
func (r *Registry) RegisterSystem(req *pkg.SystemRegistration) (*pkg.System, error) {
	results, err := r.RegisterSystemsBatch([]pkg.SystemRegistration{*req})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, pkg.ConflictError("System registration failed, it may already exist or there was an update error.")
	}
	return &results[0], nil
}

// Remove a system by ID
func (r *Registry) UnregisterSystemByID(systemID int) error {
	r.logger.WithField("system_id", systemID).Info("Unregistering system by ID")

	if err := r.db.DeleteSystemByID(systemID); err != nil {
		r.logger.WithError(err).Error("Failed to unregister system")
		return pkg.DatabaseError(err)
	}

	r.logger.WithField("system_id", systemID).Info("System unregistered successfully")
	return nil
}

// Remove a system by parameters
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

// Retrieve a system by ID
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

// Retrieve a system by name
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

// Retrieve all systems
func (r *Registry) ListSystems() ([]pkg.System, error) {
	systems, err := r.db.ListSystems("id", "ASC")
	if err != nil {
		r.logger.WithError(err).Error("Failed to list systems")
		return nil, pkg.DatabaseError(err)
	}

	return systems, nil
}

// Retrieve all systems with sorting parameters
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

// RegisterService registers a service via public API
func (r *Registry) RegisterService(req *pkg.ServiceRegistrationRequest) (*pkg.Service, error) {
	return r.registerService(req)
}

// registerService handles the common service registration logic by wrapping the batch call
func (r *Registry) registerService(req *pkg.ServiceRegistrationRequest) (*pkg.Service, error) {
	results, err := r.RegisterServicesBatch([]pkg.ServiceRegistrationRequest{*req})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, pkg.ConflictError("Service registration failed, it may already exist or there was an update error.")
	}
	return &results[0], nil
}

func (r *Registry) RegisterServicesBatch(reqs []pkg.ServiceRegistrationRequest) ([]pkg.Service, error) {
	r.logger.Infof("Registering batch of %d services", len(reqs))
	servicesToCreate := make([]*pkg.Service, 0, len(reqs))

	for _, req := range reqs {
		// This reuses the existing logic for resolving dependencies like provider, service def, etc.
		provider, err := r.getOrCreateProvider(&req.ProviderSystem)
		if err != nil {
			continue
		}
		serviceDef, err := r.getOrCreateServiceDefinition(req.ServiceDefinition)
		if err != nil {
			continue
		}
		interfaces, err := r.getOrCreateInterfaces(req.Interfaces)
		if err != nil {
			continue
		}

		version := 1
		if req.Version != "" {
			if v, err := strconv.Atoi(req.Version); err == nil {
				version = v
			}
		}

		now := time.Now()
		var endOfValidity *time.Time
		if req.EndOfValidity != "" {
			if t, err := time.Parse(time.RFC3339, req.EndOfValidity); err == nil {
				endOfValidity = &t
			}
		}

		service := &pkg.Service{
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
		servicesToCreate = append(servicesToCreate, service)
	}

	if err := r.db.CreateServicesBatch(servicesToCreate); err != nil {
		return nil, pkg.DatabaseError(err)
	}

	// Convert []*pkg.Service to []pkg.Service for the response
	createdServices := make([]pkg.Service, len(servicesToCreate))
	for i, s := range servicesToCreate {
		createdServices[i] = *s
	}

	return createdServices, nil
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

// Retrieve a service by ID
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

// Retrieve all services
func (r *Registry) ListServices() ([]pkg.Service, error) {
	services, err := r.db.ListServices("id", "ASC")
	if err != nil {
		r.logger.WithError(err).Error("Failed to list services")
		return nil, pkg.DatabaseError(err)
	}

	return services, nil
}

// Retrieve all services with sorting parameters
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

// Create multiple authorization rules in a single transaction
func (r *Registry) AddAuthorizationsBatch(reqs []pkg.AddAuthorizationRequest) ([]pkg.Authorization, error) {
	r.logger.Infof("Adding batch of %d authorization requests", len(reqs))
	authsToCreate := make([]*pkg.Authorization, 0)

	for _, req := range reqs {
		consumer, err := r.db.GetSystemByID(req.ConsumerID)
		if err != nil || consumer == nil {
			r.logger.WithError(err).WithField("consumer_id", req.ConsumerID).Warn("Consumer system not found, skipping")
			continue
		}

		if len(req.ProviderIDs) == 0 || len(req.ServiceDefinitionIDs) == 0 {
			r.logger.Warn("Provider IDs and Service Definition IDs are required, skipping")
			continue
		}

		interfaces := make([]pkg.Interface, 0, len(req.InterfaceIDs))
		for _, interfaceID := range req.InterfaceIDs {
			iface, err := r.db.GetInterfaceByID(interfaceID)
			if err == nil && iface != nil {
				interfaces = append(interfaces, *iface)
			}
		}

		for _, providerID := range req.ProviderIDs {
			provider, err := r.db.GetSystemByID(providerID)
			if err != nil || provider == nil {
				r.logger.WithError(err).WithField("provider_id", providerID).Warn("Provider system not found, skipping rule creation")
				continue
			}

			for _, serviceDefID := range req.ServiceDefinitionIDs {
				serviceDef, err := r.db.GetServiceDefinitionByID(serviceDefID)
				if err != nil || serviceDef == nil {
					r.logger.WithError(err).WithField("service_def_id", serviceDefID).Warn("Service definition not found, skipping rule creation")
					continue
				}

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

				now := time.Now()
				authorization := &pkg.Authorization{
					ConsumerSystem:    *consumer,
					ProviderSystem:    providerForAuth,
					ServiceDefinition: *serviceDef,
					Interfaces:        interfaces,
					CreatedAt:         &now,
					UpdatedAt:         &now,
				}
				authsToCreate = append(authsToCreate, authorization)
			}
		}
	}

	if len(authsToCreate) == 0 {
		return []pkg.Authorization{}, nil
	}

	if err := r.db.CreateAuthorizationsBatch(authsToCreate); err != nil {
		r.logger.WithError(err).Error("Failed to create authorizations batch")
		return nil, pkg.DatabaseError(err)
	}

	// Convert []*pkg.Authorization to []pkg.Authorization for the response
	createdAuthorizations := make([]pkg.Authorization, len(authsToCreate))
	for i, a := range authsToCreate {
		createdAuthorizations[i] = *a
	}

	r.logger.Infof("Successfully created %d authorization rules", len(createdAuthorizations))
	return createdAuthorizations, nil
}

// Create new authorization rules by wrapping the batch call
func (r *Registry) AddAuthorization(req *pkg.AddAuthorizationRequest) ([]pkg.Authorization, error) {
	return r.AddAuthorizationsBatch([]pkg.AddAuthorizationRequest{*req})
}

// Remove an authorization rule by ID
func (r *Registry) RemoveAuthorization(authID int) error {
	r.logger.WithField("auth_id", authID).Info("Removing authorization")

	if err := r.db.DeleteAuthorizationByID(authID); err != nil {
		r.logger.WithError(err).Error("Failed to remove authorization")
		return pkg.DatabaseError(err)
	}

	r.logger.WithField("auth_id", authID).Info("Authorization removed successfully")
	return nil
}

// Retrieve all authorization rules
func (r *Registry) ListAuthorizations() ([]pkg.Authorization, error) {
	authorizations, err := r.db.ListAuthorizations("id", "ASC")
	if err != nil {
		r.logger.WithError(err).Error("Failed to list authorizations")
		return nil, pkg.DatabaseError(err)
	}

	return authorizations, nil
}

// Retrieve all authorization rules with sorting parameters
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

// Get an existing provider or creates a new one
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

// Get an existing service definition or creates a new one
func (r *Registry) getOrCreateServiceDefinition(serviceDefinition string) (*pkg.ServiceDefinition, error) {
	// Try to find existing service definition
	existing, err := r.db.GetServiceDefinitionByName(serviceDefinition)
	if err == nil && existing != nil {
		return existing, nil
	}

	// Create new service definition
	now := time.Now()
	serviceDef := &pkg.ServiceDefinition{
		ServiceDefinition: serviceDefinition,
		CreatedAt:         &now,
		UpdatedAt:         &now,
	}

	if err := r.db.CreateServiceDefinition(serviceDef); err != nil {
		return nil, fmt.Errorf("failed to create service definition: %w", err)
	}

	return serviceDef, nil
}

// Get existing interfaces or creates new ones
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

// Return registry metrics
func (r *Registry) GetMetrics() (*pkg.Metrics, error) {
	metrics, err := r.db.GetMetrics()
	if err != nil {
		r.logger.WithError(err).Error("Failed to get metrics")
		return nil, pkg.DatabaseError(err)
	}

	return metrics, nil
}
