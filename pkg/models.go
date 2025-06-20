package pkg

import (
	"time"
)

// Arrowhead 4.x System Models

// SystemRegistration represents a system registration request
type SystemRegistration struct {
	SystemName         string            `json:"systemName"`
	Address            string            `json:"address"`
	Port               int               `json:"port"`
	AuthenticationInfo string            `json:"authenticationInfo"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// System represents an Arrowhead system
type System struct {
	ID                 int               `json:"id"`
	SystemName         string            `json:"systemName"`
	Address            string            `json:"address"`
	Port               int               `json:"port"`
	AuthenticationInfo string            `json:"authenticationInfo,omitempty"`
	CreatedAt          *time.Time        `json:"createdAt,omitempty"`
	UpdatedAt          *time.Time        `json:"updatedAt,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// SystemsResponse represents a paginated response of systems
type SystemsResponse struct {
	Data  []System `json:"data"`
	Count int      `json:"count"`
}

// Arrowhead 4.x Service Models

// ServiceDefinition represents a service definition
type ServiceDefinition struct {
	ID                int        `json:"id"`
	ServiceDefinition string     `json:"serviceDefinition"`
	CreatedAt         *time.Time `json:"createdAt,omitempty"`
	UpdatedAt         *time.Time `json:"updatedAt,omitempty"`
}

// Interface represents a service interface
type Interface struct {
	ID            int        `json:"id"`
	InterfaceName string     `json:"interfaceName"`
	CreatedAt     *time.Time `json:"createdAt,omitempty"`
	UpdatedAt     *time.Time `json:"updatedAt,omitempty"`
}

// Provider represents a service provider system
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

// ProviderSystem represents a provider system for service registration
type ProviderSystem struct {
	SystemName         string            `json:"systemName"`
	Address            string            `json:"address"`
	Port               int               `json:"port"`
	AuthenticationInfo string            `json:"authenticationInfo"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// ServiceRegistrationRequest represents a service registration request
type ServiceRegistrationRequest struct {
	ServiceDefinition string            `json:"serviceDefinition"`
	ProviderSystem    ProviderSystem    `json:"providerSystem"`
	ServiceUri        string            `json:"serviceUri"`
	EndOfValidity     string            `json:"endOfValidity"`
	Secure            string            `json:"secure"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	Version           string            `json:"version"`
	Interfaces        []string          `json:"interfaces"`
}

// Service represents a registered service
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

// ServicesResponse represents a paginated response of services
type ServicesResponse struct {
	Data  []Service `json:"data"`
	Count int       `json:"count"`
}

// Arrowhead 4.x Authorization Models

// AddAuthorizationRequest represents an authorization rule creation request
type AddAuthorizationRequest struct {
	ConsumerID           int   `json:"consumerId"`
	ProviderIDs          []int `json:"providerIds"`
	InterfaceIDs         []int `json:"interfaceIds"`
	ServiceDefinitionIDs []int `json:"serviceDefinitionIds"`
}

// Authorization represents an authorization rule
type Authorization struct {
	ID                int               `json:"id"`
	ConsumerSystem    System            `json:"consumerSystem"`
	ProviderSystem    Provider          `json:"providerSystem"`
	ServiceDefinition ServiceDefinition `json:"serviceDefinition"`
	Interfaces        []Interface       `json:"interfaces"`
	CreatedAt         *time.Time        `json:"createdAt,omitempty"`
	UpdatedAt         *time.Time        `json:"updatedAt,omitempty"`
}

// AuthorizationsResponse represents a paginated response of authorizations
type AuthorizationsResponse struct {
	Data  []Authorization `json:"data"`
	Count int             `json:"count"`
}

// Arrowhead 4.x Orchestration Models

// RequesterSystem represents the system requesting orchestration
type RequesterSystem struct {
	SystemName         string            `json:"systemName"`
	Address            string            `json:"address"`
	Port               int               `json:"port"`
	AuthenticationInfo string            `json:"authenticationInfo,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// OrchestrationFlags represents orchestration behavior flags
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

// Cloud represents an Arrowhead cloud
type Cloud struct {
	AuthenticationInfo string `json:"authenticationInfo"`
	GatekeeperRelayIDs []int  `json:"gatekeeperRelayIds"`
	GatewayRelayIDs    []int  `json:"gatewayRelayIds"`
	Name               string `json:"name"`
	Neighbor           bool   `json:"neighbor"`
	Operator           string `json:"operator"`
	Secure             bool   `json:"secure"`
}

// PreferredProvider represents a preferred provider for orchestration
type PreferredProvider struct {
	ProviderCloud  Cloud  `json:"providerCloud"`
	ProviderSystem System `json:"providerSystem"`
}

// RequestedService represents the service being requested in orchestration
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

// OrchestrationRequest represents a request for service orchestration
type OrchestrationRequest struct {
	RequesterSystem    RequesterSystem     `json:"requesterSystem"`
	RequestedService   RequestedService    `json:"requestedService"`
	OrchestrationFlags OrchestrationFlags  `json:"orchestrationFlags"`
	PreferredProviders []PreferredProvider `json:"preferredProviders,omitempty"`
	RequesterCloud     *Cloud              `json:"requesterCloud,omitempty"`
	QoSRequirements    map[string]string   `json:"qosRequirements,omitempty"`
	Commands           map[string]string   `json:"commands,omitempty"`
}

// MatchedService represents a service matched during orchestration
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

// OrchestrationResponse represents the response from orchestration
type OrchestrationResponse struct {
	Response []MatchedService `json:"response"`
}

// Utility models and errors

// HealthStatus represents system health information
type HealthStatus struct {
	Service   string            `json:"service"`
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Details   map[string]string `json:"details,omitempty"`
}

// Metrics represents system statistics
type Metrics struct {
	TotalSystems   int64 `json:"total_systems"`
	TotalServices  int64 `json:"total_services"`
	ActiveSystems  int64 `json:"active_systems"`
	ActiveServices int64 `json:"active_services"`
}
