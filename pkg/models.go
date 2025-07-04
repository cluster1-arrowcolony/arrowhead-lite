package pkg

import (
	"time"
)

// A system registration request
type SystemRegistration struct {
	SystemName         string            `json:"systemName"`
	Address            string            `json:"address"`
	Port               int               `json:"port"`
	AuthenticationInfo string            `json:"authenticationInfo"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// An Arrowhead system
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

// A service registration request
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

// A request for service orchestration
type OrchestrationRequest struct {
	RequesterSystem    RequesterSystem     `json:"requesterSystem"`
	RequestedService   RequestedService    `json:"requestedService"`
	OrchestrationFlags OrchestrationFlags  `json:"orchestrationFlags"`
	PreferredProviders []PreferredProvider `json:"preferredProviders,omitempty"`
	RequesterCloud     *Cloud              `json:"requesterCloud,omitempty"`
	QoSRequirements    map[string]string   `json:"qosRequirements,omitempty"`
	Commands           map[string]string   `json:"commands,omitempty"`
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
