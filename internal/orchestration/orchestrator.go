package orchestration

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/database"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// AuthManager interface for token generation
type AuthManager interface {
	GenerateServiceToken(consumerID, providerID, serviceID int) (string, error)
}

type Orchestrator struct {
	db          database.Database
	authManager AuthManager
	logger      *logrus.Logger
}

func NewOrchestrator(db database.Database, authManager AuthManager, logger *logrus.Logger) *Orchestrator {
	return &Orchestrator{
		db:          db,
		authManager: authManager,
		logger:      logger,
	}
}

// Orchestrate performs service orchestration for Arrowhead 4.x OrchestrationRequest
func (o *Orchestrator) Orchestrate(req *pkg.OrchestrationRequest) (*pkg.OrchestrationResponse, error) {
	o.logger.WithFields(logrus.Fields{
		"requester_system": req.RequesterSystem.SystemName,
		"service_def":      req.RequestedService.ServiceDefinitionRequirement,
		"interfaces":       req.RequestedService.InterfaceRequirements,
		"flags":           req.OrchestrationFlags,
	}).Debug("Processing orchestration request")

	// Find services matching the request
	matchingServices, err := o.findMatchingServices(req)
	if err != nil {
		o.logger.WithError(err).Error("Failed to find matching services")
		return nil, pkg.InternalServerError("Failed to find matching services")
	}

	// Apply orchestration flags and filtering
	filteredServices := o.applyOrchestrationFlags(matchingServices, req)

	// Apply preferred providers if specified
	rankedServices := o.applyPreferredProviders(filteredServices, req.PreferredProviders)

	// Apply QoS requirements if specified
	if len(req.QoSRequirements) > 0 {
		rankedServices = o.applyQoSFiltering(rankedServices, req.QoSRequirements)
	}

	// Apply metadata search if enabled
	if req.OrchestrationFlags.MetadataSearch {
		rankedServices = o.applyMetadataFiltering(rankedServices, req.RequestedService.MetadataRequirements)
	}

	// Convert to MatchedService format and generate authorization tokens
	matchedServices := make([]pkg.MatchedService, 0, len(rankedServices))
	for _, service := range rankedServices {
		matchedService, err := o.createMatchedService(service, req)
		if err != nil {
			o.logger.WithError(err).WithField("service_id", service.ID).Warn("Failed to create matched service")
			continue
		}
		matchedServices = append(matchedServices, *matchedService)
	}

	o.logger.WithFields(logrus.Fields{
		"requester_system": req.RequesterSystem.SystemName,
		"service_def":      req.RequestedService.ServiceDefinitionRequirement,
		"found_services":   len(matchingServices),
		"returned_services": len(matchedServices),
	}).Info("Orchestration completed")

	return &pkg.OrchestrationResponse{Response: matchedServices}, nil
}

// findMatchingServices finds services that match the orchestration request
func (o *Orchestrator) findMatchingServices(req *pkg.OrchestrationRequest) ([]pkg.Service, error) {
	// Get all services from the database (in a real implementation, this would be optimized)
	allServices, err := o.db.ListServices("id", "ASC")
	if err != nil {
		return nil, err
	}

	matchingServices := make([]pkg.Service, 0)
	
	for _, service := range allServices {
		// Check service definition match
		if !o.matchesServiceDefinition(service, req.RequestedService.ServiceDefinitionRequirement) {
			continue
		}

		// Check interface requirements
		if !o.matchesInterfaceRequirements(service, req.RequestedService.InterfaceRequirements) {
			continue
		}

		// Check security requirements
		if !o.matchesSecurityRequirements(service, req.RequestedService.SecurityRequirements) {
			continue
		}

		// Check version requirements
		if !o.matchesVersionRequirements(service, req.RequestedService) {
			continue
		}

		// Check authorization (consumer must be authorized to access this service)
		if !o.isAuthorized(req.RequesterSystem, service) {
			continue
		}

		matchingServices = append(matchingServices, service)
	}

	return matchingServices, nil
}


// matchesServiceDefinition checks if the service matches the requested service definition
func (o *Orchestrator) matchesServiceDefinition(service pkg.Service, required string) bool {
	return strings.EqualFold(service.ServiceDefinition.ServiceDefinition, required)
}

// matchesInterfaceRequirements checks if the service provides required interfaces
func (o *Orchestrator) matchesInterfaceRequirements(service pkg.Service, required []string) bool {
	if len(required) == 0 {
		return true // No specific interface requirements
	}

	serviceInterfaces := make(map[string]bool)
	for _, iface := range service.Interfaces {
		serviceInterfaces[strings.ToUpper(iface.InterfaceName)] = true
	}

	for _, requiredInterface := range required {
		if !serviceInterfaces[strings.ToUpper(requiredInterface)] {
			return false
		}
	}

	return true
}

// matchesSecurityRequirements checks if the service meets security requirements
func (o *Orchestrator) matchesSecurityRequirements(service pkg.Service, required []string) bool {
	if len(required) == 0 {
		return true // No specific security requirements
	}

	// For now, we'll accept TOKEN security for all requirements
	// In a full implementation, this would be more sophisticated
	serviceSecurity := strings.ToUpper(service.Secure)
	
	for _, requiredSecurity := range required {
		requiredSecurity = strings.ToUpper(requiredSecurity)
		if requiredSecurity == "TOKEN" && serviceSecurity == "TOKEN" {
			continue
		}
		if requiredSecurity == "CERTIFICATE" && serviceSecurity == "CERTIFICATE" {
			continue
		}
		// Add more security matching logic as needed
		return false
	}

	return true
}

// matchesVersionRequirements checks if the service version meets requirements
func (o *Orchestrator) matchesVersionRequirements(service pkg.Service, requested pkg.RequestedService) bool {
	serviceVersion := service.Version

	if requested.VersionRequirement != nil {
		if serviceVersion != *requested.VersionRequirement {
			return false
		}
	}

	if requested.MinVersionRequirement != nil {
		if serviceVersion < *requested.MinVersionRequirement {
			return false
		}
	}

	if requested.MaxVersionRequirement != nil {
		if serviceVersion > *requested.MaxVersionRequirement {
			return false
		}
	}

	return true
}

// isAuthorized checks if the requester is authorized to access the service
func (o *Orchestrator) isAuthorized(requester pkg.RequesterSystem, service pkg.Service) bool {
	// Get requester system from database to get its ID
	requesterSystem, err := o.db.GetSystemByName(requester.SystemName)
	if err != nil || requesterSystem == nil {
		o.logger.WithField("requester", requester.SystemName).Warn("Requester system not found")
		return false
	}

	// Extract interface IDs for authorization check
	interfaceIDs := make([]int, len(service.Interfaces))
	for i, iface := range service.Interfaces {
		interfaceIDs[i] = iface.ID
	}

	// Check authorization in database
	authorized, err := o.db.CheckAuthorization(
		requesterSystem.ID,
		service.Provider.ID,
		service.ServiceDefinition.ID,
		interfaceIDs,
	)
	if err != nil {
		o.logger.WithError(err).WithFields(logrus.Fields{
			"requester":    requester.SystemName,
			"provider":     service.Provider.SystemName,
			"service":      service.ServiceDefinition.ServiceDefinition,
		}).Warn("Authorization check failed")
		return false
	}

	if !authorized {
		o.logger.WithFields(logrus.Fields{
			"requester":    requester.SystemName,
			"provider":     service.Provider.SystemName,
			"service":      service.ServiceDefinition.ServiceDefinition,
		}).Debug("Access denied: no authorization rule found")
	}

	return authorized
}

// applyOrchestrationFlags applies orchestration flags to filter services
func (o *Orchestrator) applyOrchestrationFlags(services []pkg.Service, req *pkg.OrchestrationRequest) []pkg.Service {
	// Apply various orchestration flags
	// For now, we'll implement basic functionality
	
	if req.OrchestrationFlags.OnlyPreferred && len(req.PreferredProviders) > 0 {
		// Filter to only preferred providers
		preferredServices := make([]pkg.Service, 0)
		for _, service := range services {
			for _, preferred := range req.PreferredProviders {
				if service.Provider.SystemName == preferred.ProviderSystem.SystemName {
					preferredServices = append(preferredServices, service)
					break
				}
			}
		}
		return preferredServices
	}

	return services
}

// applyPreferredProviders ranks services based on preferred providers
func (o *Orchestrator) applyPreferredProviders(services []pkg.Service, preferred []pkg.PreferredProvider) []pkg.Service {
	if len(preferred) == 0 {
		return services
	}

	// Create a preference map
	preferenceMap := make(map[string]int)
	for i, pref := range preferred {
		preferenceMap[pref.ProviderSystem.SystemName] = len(preferred) - i // Higher score for earlier preferences
	}

	// Sort services by preference
	sort.Slice(services, func(i, j int) bool {
		scoreI := preferenceMap[services[i].Provider.SystemName]
		scoreJ := preferenceMap[services[j].Provider.SystemName]
		return scoreI > scoreJ
	})

	return services
}

// applyQoSFiltering applies QoS requirements filtering
func (o *Orchestrator) applyQoSFiltering(services []pkg.Service, qosReqs map[string]string) []pkg.Service {
	// For now, return all services
	// TODO: Implement QoS filtering based on requirements
	return services
}

// applyMetadataFiltering applies metadata-based filtering
func (o *Orchestrator) applyMetadataFiltering(services []pkg.Service, metadataReqs map[string]string) []pkg.Service {
	if len(metadataReqs) == 0 {
		return services
	}

	filteredServices := make([]pkg.Service, 0)
	for _, service := range services {
		matches := true
		for key, value := range metadataReqs {
			if service.Metadata == nil {
				matches = false
				break
			}
			if serviceValue, exists := service.Metadata[key]; !exists || serviceValue != value {
				matches = false
				break
			}
		}
		if matches {
			filteredServices = append(filteredServices, service)
		}
	}

	return filteredServices
}

// createMatchedService creates a MatchedService from a Service
func (o *Orchestrator) createMatchedService(service pkg.Service, req *pkg.OrchestrationRequest) (*pkg.MatchedService, error) {
	// Generate authorization token
	authTokens := make(map[string]string)
	for _, iface := range service.Interfaces {
		token, err := o.generateAuthorizationToken(req.RequesterSystem, service, iface.InterfaceName)
		if err != nil {
			o.logger.WithError(err).Warn("Failed to generate authorization token")
		} else {
			authTokens[iface.InterfaceName] = token
		}
	}

	// Check if ping is required
	warnings := make([]string, 0)
	if req.RequestedService.PingProviders || req.OrchestrationFlags.PingProviders {
		// TODO: Implement provider pinging
		warnings = append(warnings, "Provider ping not implemented")
	}

	matchedService := &pkg.MatchedService{
		Provider:            service.Provider,
		Service:             service.ServiceDefinition,
		ServiceUri:          service.ServiceUri,
		Secure:              service.Secure,
		Metadata:            service.Metadata,
		Interfaces:          service.Interfaces,
		Version:             service.Version,
		AuthorizationTokens: authTokens,
		Warnings:            warnings,
	}

	return matchedService, nil
}

// generateAuthorizationToken generates an authorization token for service access
func (o *Orchestrator) generateAuthorizationToken(requester pkg.RequesterSystem, service pkg.Service, interfaceName string) (string, error) {
	// Get requester system from database to get its ID
	requesterSystem, err := o.db.GetSystemByName(requester.SystemName)
	if err != nil || requesterSystem == nil {
		o.logger.WithField("requester", requester.SystemName).Error("Requester system not found for token generation")
		return "", fmt.Errorf("requester system not found: %s", requester.SystemName)
	}

	// Generate proper JWT token using AuthManager
	if o.authManager != nil {
		token, err := o.authManager.GenerateServiceToken(
			requesterSystem.ID,
			service.Provider.ID,
			service.ID,
		)
		if err != nil {
			o.logger.WithError(err).Warn("Failed to generate JWT token, falling back to simple token")
		} else {
			return token, nil
		}
	}

	// Fallback to simple token generation if AuthManager is not available or fails
	tokenData := fmt.Sprintf("%s:%s:%s:%d", 
		requester.SystemName, 
		service.ServiceDefinition.ServiceDefinition,
		interfaceName,
		time.Now().Unix())
	
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	
	token := hex.EncodeToString(randomBytes) + ":" + tokenData
	return token, nil
}

