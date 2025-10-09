// Package pkg provides Arrowhead Framework 4.x compatible data models and types.
//
// This package defines the core domain models used across the Arrowhead IoT service mesh,
// including system registration, service discovery, authorization, and orchestration.
// All types are designed for JSON serialization and conform to the Arrowhead 4.x REST API specification.
package pkg

import (
	"time"
)

// SystemRegistration represents a request to register a new IoT system with the
// Arrowhead service registry. Systems must register before they can provide or
// consume services in the local cloud.
//
// The AuthenticationInfo field should contain a certificate thumbprint (SHA-256)
// when using mTLS authentication in production mode.
type SystemRegistration struct {
	SystemName         string            `json:"systemName"`         // Unique identifier for the system
	Address            string            `json:"address"`            // IP address or hostname
	Port               int               `json:"port"`               // Port number where the system is accessible
	AuthenticationInfo string            `json:"authenticationInfo"` // Certificate thumbprint for mTLS or empty for dev mode
	Metadata           map[string]string `json:"metadata,omitempty"` // Optional key-value metadata
}

// System represents a registered IoT system in the Arrowhead local cloud.
// Systems are the fundamental entities that provide and consume services.
// This type is returned by the Service Registry after successful registration.
type System struct {
	ID                 int               `json:"id"`                           // Database-assigned unique identifier
	SystemName         string            `json:"systemName"`                   // Unique name of the system
	Address            string            `json:"address"`                      // IP address or hostname
	Port               int               `json:"port"`                         // Port number
	AuthenticationInfo string            `json:"authenticationInfo,omitempty"` // Certificate thumbprint for mTLS
	CreatedAt          *time.Time        `json:"createdAt,omitempty"`          // Timestamp of initial registration
	UpdatedAt          *time.Time        `json:"updatedAt,omitempty"`          // Timestamp of last update
	Metadata           map[string]string `json:"metadata,omitempty"`           // Custom key-value metadata
}

// A paginated response of systems
type SystemsResponse struct {
	Data  []System `json:"data"`
	Count int      `json:"count"`
}

// A service definition
type ServiceDefinition struct {
	ID                int        `json:"id"`
	ServiceDefinition string     `json:"serviceDefinition"`
	CreatedAt         *time.Time `json:"createdAt,omitempty"`
	UpdatedAt         *time.Time `json:"updatedAt,omitempty"`
}

// A service interface
type Interface struct {
	ID            int        `json:"id"`
	InterfaceName string     `json:"interfaceName"`
	CreatedAt     *time.Time `json:"createdAt,omitempty"`
	UpdatedAt     *time.Time `json:"updatedAt,omitempty"`
}

// A service provider system
// TODO: How does this differ from ProviderSystem?
type Provider struct {
	ID                 int               `json:"id"`
	SystemName         string            `json:"systemName"`
	Address            string            `json:"address"`
	Port               int               `json:"port"`
	AuthenticationInfo string            `json:"authenticationInfo"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	CreatedAt          *time.Time        `json:"createdAt,omitempty"`
	UpdatedAt          *time.Time        `json:"updatedAt,omitempty"`
}

// A provider system for service registration
type ProviderSystem struct {
	SystemName         string            `json:"systemName"`
	Address            string            `json:"address"`
	Port               int               `json:"port"`
	AuthenticationInfo string            `json:"authenticationInfo"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// ServiceRegistrationRequest represents a request to register a service with the
// Arrowhead service registry. Services define capabilities that provider systems
// offer to consumer systems.
//
// The Secure field should be "TOKEN", "CERTIFICATE", or "NOT_SECURE".
// The EndOfValidity field uses RFC3339 format (e.g., "2024-12-31T23:59:59Z").
type ServiceRegistrationRequest struct {
	ServiceDefinition string            `json:"serviceDefinition"`  // Name of the service (e.g., "temperature-sensor")
	ProviderSystem    ProviderSystem    `json:"providerSystem"`     // System providing this service
	ServiceUri        string            `json:"serviceUri"`         // URI path for accessing the service
	EndOfValidity     string            `json:"endOfValidity"`      // Optional expiration time in RFC3339 format
	Secure            string            `json:"secure"`             // Security type: TOKEN, CERTIFICATE, or NOT_SECURE
	Metadata          map[string]string `json:"metadata,omitempty"` // Optional service metadata
	Version           string            `json:"version"`            // Service version number
	Interfaces        []string          `json:"interfaces"`         // Supported interfaces (e.g., "HTTP-SECURE-JSON")
}

// A registered service
type Service struct {
	ID                int               `json:"id"`
	ServiceDefinition ServiceDefinition `json:"serviceDefinition"`
	Provider          Provider          `json:"provider"`
	ServiceUri        string            `json:"serviceUri"`
	EndOfValidity     *time.Time        `json:"endOfValidity,omitempty"`
	Secure            string            `json:"secure"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	Version           int               `json:"version"`
	Interfaces        []Interface       `json:"interfaces"`
	CreatedAt         *time.Time        `json:"createdAt,omitempty"`
	UpdatedAt         *time.Time        `json:"updatedAt,omitempty"`
}

// A paginated response of services
type ServicesResponse struct {
	Data  []Service `json:"data"`
	Count int       `json:"count"`
}

// An authorization rule creation request
type AddAuthorizationRequest struct {
	ConsumerID           int   `json:"consumerId"`
	ProviderIDs          []int `json:"providerIds"`
	InterfaceIDs         []int `json:"interfaceIds"`
	ServiceDefinitionIDs []int `json:"serviceDefinitionIds"`
}

// An authorization rule
type Authorization struct {
	ID                int               `json:"id"`
	ConsumerSystem    System            `json:"consumerSystem"`
	ProviderSystem    Provider          `json:"providerSystem"`
	ServiceDefinition ServiceDefinition `json:"serviceDefinition"`
	Interfaces        []Interface       `json:"interfaces"`
	CreatedAt         *time.Time        `json:"createdAt,omitempty"`
	UpdatedAt         *time.Time        `json:"updatedAt,omitempty"`
}

// A paginated response of authorizations
type AuthorizationsResponse struct {
	Data  []Authorization `json:"data"`
	Count int             `json:"count"`
}

// A system requesting orchestration
type RequesterSystem struct {
	SystemName         string            `json:"systemName"`
	Address            string            `json:"address"`
	Port               int               `json:"port"`
	AuthenticationInfo string            `json:"authenticationInfo,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// Orchestration behavior flags
type OrchestrationFlags struct {
	OnlyPreferred          bool `json:"onlyPreferred"`
	OverrideStore          bool `json:"overrideStore"`
	ExternalServiceRequest bool `json:"externalServiceRequest"`
	EnableInterCloud       bool `json:"enableInterCloud"`
	EnableQoS              bool `json:"enableQoS"`
	Matchmaking            bool `json:"matchmaking"`
	MetadataSearch         bool `json:"metadataSearch"`
	TriggerInterCloud      bool `json:"triggerInterCloud"`
	PingProviders          bool `json:"pingProviders"`
}

// An Arrowhead cloud
type Cloud struct {
	AuthenticationInfo string `json:"authenticationInfo"`
	GatekeeperRelayIDs []int  `json:"gatekeeperRelayIds"`
	GatewayRelayIDs    []int  `json:"gatewayRelayIds"`
	Name               string `json:"name"`
	Neighbor           bool   `json:"neighbor"`
	Operator           string `json:"operator"`
	Secure             bool   `json:"secure"`
}

// A preferred provider for orchestration
type PreferredProvider struct {
	ProviderCloud  Cloud  `json:"providerCloud"`
	ProviderSystem System `json:"providerSystem"`
}

// A service being requested in orchestration
type RequestedService struct {
	ServiceDefinitionRequirement string            `json:"serviceDefinitionRequirement"`
	InterfaceRequirements        []string          `json:"interfaceRequirements"`
	SecurityRequirements         []string          `json:"securityRequirements"`
	MetadataRequirements         map[string]string `json:"metadataRequirements,omitempty"`
	VersionRequirement           *int              `json:"versionRequirement,omitempty"`
	MaxVersionRequirement        *int              `json:"maxVersionRequirement,omitempty"`
	MinVersionRequirement        *int              `json:"minVersionRequirement,omitempty"`
	PingProviders                bool              `json:"pingProviders"`
}

// OrchestrationRequest represents a request for service orchestration.
// Consumer systems use this to discover and get recommendations for service providers
// that match their requirements.
//
// The orchestrator will:
//  1. Find services matching the ServiceDefinitionRequirement
//  2. Filter by interface, security, and version requirements
//  3. Check authorization rules
//  4. Apply preferred providers and QoS filtering
//  5. Return ranked service recommendations with authorization tokens
type OrchestrationRequest struct {
	RequesterSystem    RequesterSystem     `json:"requesterSystem"`              // System requesting orchestration
	RequestedService   RequestedService    `json:"requestedService"`             // Service requirements and filters
	OrchestrationFlags OrchestrationFlags  `json:"orchestrationFlags"`           // Behavioral flags
	PreferredProviders []PreferredProvider `json:"preferredProviders,omitempty"` // Preferred service providers (ranked)
	RequesterCloud     *Cloud              `json:"requesterCloud,omitempty"`     // Cloud information (for inter-cloud)
	QoSRequirements    map[string]string   `json:"qosRequirements,omitempty"`    // Quality of Service requirements
	Commands           map[string]string   `json:"commands,omitempty"`           // Custom orchestration commands
}

// A service matched during orchestration
type MatchedService struct {
	Provider            Provider          `json:"provider"`
	Service             ServiceDefinition `json:"service"` // Note: field name is "service" not "serviceDefinition"
	ServiceUri          string            `json:"serviceUri"`
	Secure              string            `json:"secure"`
	Metadata            map[string]string `json:"metadata,omitempty"`
	Interfaces          []Interface       `json:"interfaces"`
	Version             int               `json:"version"`
	AuthorizationTokens map[string]string `json:"authorizationTokens,omitempty"`
	Warnings            []string          `json:"warnings,omitempty"`
}

// A response from orchestration
type OrchestrationResponse struct {
	Response []MatchedService `json:"response"`
}

// System health information
type HealthStatus struct {
	Service   string            `json:"service"`
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Details   map[string]string `json:"details,omitempty"`
}

// System statistics
type Metrics struct {
	TotalSystems   int64 `json:"total_systems"`
	TotalServices  int64 `json:"total_services"`
	ActiveSystems  int64 `json:"active_systems"`
	ActiveServices int64 `json:"active_services"`
}
