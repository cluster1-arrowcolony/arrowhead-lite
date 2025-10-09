// Package orchestration implements the Arrowhead Orchestrator core system.
//
// The Orchestrator provides dynamic service matching and provider recommendations
// for consumer systems within an Arrowhead local cloud. It implements the
// Arrowhead Framework 4.x Orchestrator specification.
//
// Key responsibilities:
//   - Service discovery and matching based on consumer requirements
//   - Provider ranking using preferred providers and QoS requirements
//   - Authorization-aware service filtering
//   - Metadata-based service selection
//   - Authorization token generation for matched services
//
// The orchestration process filters and ranks services based on:
//   - Service definition matching
//   - Interface compatibility
//   - Security requirements
//   - Version constraints
//   - Authorization rules
//   - Preferred providers
//   - QoS requirements
//   - Metadata matching
package orchestration

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/auth"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/database"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Orchestrator implements service discovery and matching for consumer systems.
// It filters and ranks available services based on consumer requirements.
type Orchestrator struct {
	db          database.Database
	authManager *auth.AuthManager
	logger      *logrus.Logger
}

// NewOrchestrator creates a new Orchestrator instance with the provided dependencies.
// The orchestrator is immediately ready to handle orchestration requests.
func NewOrchestrator(db database.Database, authManager *auth.AuthManager, logger *logrus.Logger) *Orchestrator {
	return &Orchestrator{
		db:          db,
		authManager: authManager,
		logger:      logger,
	}
}

// Orchestrate processes an orchestration request and returns matching services.
//
// The orchestration process:
//  1. Finds all services matching the service definition requirement
//  2. Filters by interface, security, and version requirements
//  3. Checks authorization rules (consumer must be authorized)
//  4. Applies orchestration flags (e.g., onlyPreferred)
//  5. Ranks results using preferred providers
//  6. Applies QoS and metadata filtering
//  7. Generates authorization tokens for matched services
//
// Returns an OrchestrationResponse containing ranked service recommendations
// with authorization tokens for each interface.
//
// Returns pkg.InternalServerError if service discovery or matching fails.
func (o *Orchestrator) Orchestrate(req *pkg.OrchestrationRequest) (*pkg.OrchestrationResponse, error) {
	o.logger.WithFields(logrus.Fields{
		"requester_system": req.RequesterSystem.SystemName,
		"service_def":      req.RequestedService.ServiceDefinitionRequirement,
		"interfaces":       req.RequestedService.InterfaceRequirements,
		"flags":            req.OrchestrationFlags,
	}).Debug("Processing orchestration request")

	matchingServices, err := o.findMatchingServices(req)
	if err != nil {
		o.logger.WithError(err).Error("Failed to find matching services")
		return nil, pkg.InternalServerError("Failed to find matching services")
	}

	filteredServices := o.applyOrchestrationFlags(matchingServices, req)
	rankedServices := o.applyPreferredProviders(filteredServices, req.PreferredProviders)
	if len(req.QoSRequirements) > 0 {
		rankedServices = o.applyQoSFiltering(rankedServices, req.QoSRequirements)
	}
	if req.OrchestrationFlags.MetadataSearch {
		rankedServices = o.applyMetadataFiltering(rankedServices, req.RequestedService.MetadataRequirements)
	}
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
		"requester_system":  req.RequesterSystem.SystemName,
		"service_def":       req.RequestedService.ServiceDefinitionRequirement,
		"found_services":    len(matchingServices),
		"returned_services": len(matchedServices),
	}).Info("Orchestration completed")

	return &pkg.OrchestrationResponse{Response: matchedServices}, nil
}

func (o *Orchestrator) findMatchingServices(req *pkg.OrchestrationRequest) ([]pkg.Service, error) {
	services, err := o.db.ListServices("id", "ASC")
	if err != nil {
		return nil, err
	}

	matchingServices := make([]pkg.Service, 0)

	for _, service := range services {
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

// Checks if the service matches the requested service definition
func (o *Orchestrator) matchesServiceDefinition(service pkg.Service, required string) bool {
	return strings.EqualFold(service.ServiceDefinition.ServiceDefinition, required)
}

// Checks if the service provides required interfaces
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

// Checks if the service meets security requirements
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

// Checks if the service version meets requirements
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

// Checks if the requester is authorized to access the service
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
			"requester": requester.SystemName,
			"provider":  service.Provider.SystemName,
			"service":   service.ServiceDefinition.ServiceDefinition,
		}).Warn("Authorization check failed")
		return false
	}

	if !authorized {
		o.logger.WithFields(logrus.Fields{
			"requester": requester.SystemName,
			"provider":  service.Provider.SystemName,
			"service":   service.ServiceDefinition.ServiceDefinition,
		}).Debug("Access denied: no authorization rule found")
	}

	return authorized
}

// Applies orchestration flags to filter services
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

// Ranks services based on preferred providers
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

// Apply QoS requirements filtering
func (o *Orchestrator) applyQoSFiltering(services []pkg.Service, qosReqs map[string]string) []pkg.Service {
	// TODO: Not yet implemented
	if len(qosReqs) > 0 {
		o.logger.Debug("QoS filtering is not implemented in arrowhead-lite, returning all services.")
	}
	return services
}

// Apply metadata-based filtering
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

// Create a MatchedService from a Service
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
		// TODO: Implement provider ping logic
		o.logger.WithFields(logrus.Fields{
			"provider": service.Provider.SystemName,
			"service":  service.ServiceDefinition.ServiceDefinition,
		}).Debug("Provider ping requested but is not implemented in arrowhead-lite.")
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

// Generate an authorization token for service access
func (o *Orchestrator) generateAuthorizationToken(requester pkg.RequesterSystem, service pkg.Service, interfaceName string) (string, error) {
	// Get requester system from database to get its ID
	requesterSystem, err := o.db.GetSystemByName(requester.SystemName)
	if err != nil || requesterSystem == nil {
		o.logger.WithField("requester", requester.SystemName).Error("Requester system not found for token generation")
		return "", fmt.Errorf("requester system not found: %s", requester.SystemName)
	}

	// Generate proper JWT token using AuthManager
	token, err := o.authManager.GenerateServiceToken(requesterSystem.ID, service.Provider.ID, service.ID)
	if err == nil {
		return token, nil
	}
	o.logger.WithError(err).Warn("Failed to generate JWT token, falling back to simple token")

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

	return hex.EncodeToString(randomBytes) + ":" + tokenData, nil
}
