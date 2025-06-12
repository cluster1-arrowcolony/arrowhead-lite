package registry

import (
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RegisterService registers a new service in the registry
func (r *Registry) RegisterService(req *pkg.RegistrationRequest) (*pkg.Service, error) {
	service := &req.Service
	node := &req.Node

	if service.ID == "" {
		service.ID = uuid.New().String()
	}

	if node.ID != "" && service.NodeID == "" {
		service.NodeID = node.ID
	}

	if service.NodeID == "" {
		return nil, pkg.BadRequestError("Node ID is required for service registration")
	}

	existingNode, err := r.db.GetNode(service.NodeID)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get node")
		return nil, pkg.DatabaseError(err)
	}

	if existingNode == nil {
		return nil, pkg.NotFoundError("Node not found")
	}

	now := time.Now()
	service.CreatedAt = now
	service.UpdatedAt = now
	service.LastSeen = now
	service.Status = pkg.ServiceStatusActive

	if service.Version == "" {
		service.Version = "1.0"
	}

	if service.Metadata == nil {
		service.Metadata = make(map[string]string)
	}

	if err := r.db.CreateService(service); err != nil {
		r.logger.WithError(err).Error("Failed to create service")
		return nil, pkg.DatabaseError(err)
	}

	existingNode.LastSeen = now
	if err := r.db.UpdateNode(existingNode); err != nil {
		r.logger.WithError(err).Warn("Failed to update node last seen")
	}

	r.logger.WithFields(logrus.Fields{
		"service_id":   service.ID,
		"service_name": service.Name,
		"node_id":      service.NodeID,
		"definition":   service.Definition,
		"uri":          service.URI,
		"method":       service.Method,
	}).Info("Service registered successfully")

	return service, nil
}

// UnregisterService removes a service from the registry
func (r *Registry) UnregisterService(serviceID string) error {
	existing, err := r.db.GetService(serviceID)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get service")
		return pkg.DatabaseError(err)
	}

	if existing == nil {
		return pkg.NotFoundError("Service not found")
	}

	if err := r.db.DeleteService(serviceID); err != nil {
		r.logger.WithError(err).Error("Failed to delete service")
		return pkg.DatabaseError(err)
	}

	r.logger.WithFields(logrus.Fields{
		"service_id":   serviceID,
		"service_name": existing.Name,
		"node_id":      existing.NodeID,
	}).Info("Service unregistered successfully")

	return nil
}

// GetService retrieves a service by ID
func (r *Registry) GetService(serviceID string) (*pkg.Service, error) {
	service, err := r.db.GetService(serviceID)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get service")
		return nil, pkg.DatabaseError(err)
	}

	if service == nil {
		return nil, pkg.NotFoundError("Service not found")
	}

	return service, nil
}

// ListServices returns all registered services
func (r *Registry) ListServices() ([]*pkg.Service, error) {
	services, err := r.db.ListServices()
	if err != nil {
		r.logger.WithError(err).Error("Failed to list services")
		return nil, pkg.DatabaseError(err)
	}

	return services, nil
}

// ListServicesByNode returns all services registered by a specific node
func (r *Registry) ListServicesByNode(nodeID string) ([]*pkg.Service, error) {
	_, err := r.db.GetNode(nodeID)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get node")
		return nil, pkg.DatabaseError(err)
	}

	services, err := r.db.GetServicesByNode(nodeID)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get services by node")
		return nil, pkg.DatabaseError(err)
	}

	return services, nil
}

// FindServicesByName finds services by name
func (r *Registry) FindServicesByName(name string) ([]*pkg.Service, error) {
	services, err := r.db.GetServicesByName(name)
	if err != nil {
		r.logger.WithError(err).Error("Failed to find services by name")
		return nil, pkg.DatabaseError(err)
	}

	return services, nil
}

// UpdateServiceHealth updates the health status of a service
func (r *Registry) UpdateServiceHealth(serviceID string, status pkg.ServiceStatus) error {
	service, err := r.db.GetService(serviceID)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get service for health update")
		return pkg.DatabaseError(err)
	}

	if service == nil {
		return pkg.NotFoundError("Service not found")
	}

	service.LastSeen = time.Now()
	service.Status = status

	if err := r.db.UpdateService(service); err != nil {
		r.logger.WithError(err).Error("Failed to update service health")
		return pkg.DatabaseError(err)
	}

	return nil
}
