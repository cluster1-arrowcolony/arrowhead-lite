package pkg

import (
	"time"
)

// A service provided and/or consumed by a node.
type Service struct {
	ID          string            `json:"id" db:"id"`
	Name        string            `json:"name" db:"name"`
	NodeID      string            `json:"node_id" db:"node_id"`
	Definition  string            `json:"definition" db:"definition"`
	URI         string            `json:"uri" db:"uri"`
	Method      string            `json:"method" db:"method"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Version     string            `json:"version" db:"version"`
	Status      ServiceStatus     `json:"status" db:"status"`
	HealthCheck string            `json:"health_check" db:"health_check"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	LastSeen    time.Time         `json:"last_seen" db:"last_seen"`
}

// A node that provides and/or consumes services.
type Node struct {
	ID              string            `json:"id" db:"id"`
	Name            string            `json:"name" db:"name"`
	Address         string            `json:"address" db:"address"`
	Port            int               `json:"port" db:"port"`
	Certificate     string            `json:"certificate,omitempty" db:"certificate"`
	CertificateHash string            `json:"certificate_hash,omitempty" db:"certificate_hash"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	Status          NodeStatus        `json:"status" db:"status"`
	CreatedAt       time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at" db:"updated_at"`
	LastSeen        time.Time         `json:"last_seen" db:"last_seen"`
}

// An authorization rule for a service, defining which consumer can access which provider's service.
type AuthRule struct {
	ID         string    `json:"id" db:"id"`
	ConsumerID string    `json:"consumer_id" db:"consumer_id"`
	ProviderID string    `json:"provider_id" db:"provider_id"`
	ServiceID  string    `json:"service_id" db:"service_id"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// An authorization rule with resolved names for display purposes.
type AuthRuleWithNames struct {
	ID           string    `json:"id"`
	ConsumerID   string    `json:"consumer_id"`
	ConsumerName string    `json:"consumer_name"`
	ProviderID   string    `json:"provider_id"`
	ProviderName string    `json:"provider_name"`
	ServiceID    string    `json:"service_id"`
	ServiceName  string    `json:"service_name"`
	CreatedAt    time.Time `json:"created_at"`
}

// A request to orchestrate services, allowing a requester to find and access services based on filters and preferences.
type OrchestrationRequest struct {
	RequesterID string                 `json:"requester_id"`
	ServiceName string                 `json:"service_name"`
	Filters     map[string]interface{} `json:"filters,omitempty"`
	Preferences map[string]interface{} `json:"preferences,omitempty"`
}

// A response from the orchestration service, containing a list of services that match the requester's criteria.
type OrchestrationResponse struct {
	Services []ServiceResponse `json:"services"`
}

// A response containing details about a service, including its node and access information.
type ServiceResponse struct {
	Service       Service           `json:"service"`
	Node          Node              `json:"node"`
	AccessToken   string            `json:"access_token,omitempty"`
	Endpoint      string            `json:"endpoint"`
	Authorization map[string]string `json:"authorization,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// A message or notification that can be published to a topic.
type Event struct {
	ID          string            `json:"id" db:"id"`
	Type        string            `json:"type" db:"type"`
	Topic       string            `json:"topic" db:"topic"`
	PublisherID string            `json:"publisher_id" db:"publisher_id"`
	Payload     []byte            `json:"payload" db:"payload"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
}

// A subscription to a topic, allowing a subscriber to receive events published to that topic.
type Subscription struct {
	ID           string            `json:"id" db:"id"`
	SubscriberID string            `json:"subscriber_id" db:"subscriber_id"`
	Topic        string            `json:"topic" db:"topic"`
	Endpoint     string            `json:"endpoint" db:"endpoint"`
	Filters      map[string]string `json:"filters,omitempty"`
	CreatedAt    time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at" db:"updated_at"`
}

// Health status of a service, including its current status and any additional details.
type HealthStatus struct {
	Service   string            `json:"service"`
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Details   map[string]string `json:"details,omitempty"`
}

// Status of a service, indicating whether it is active, inactive, healthy, or unhealthy.
type ServiceStatus string

const (
	ServiceStatusActive    ServiceStatus = "active"
	ServiceStatusInactive  ServiceStatus = "inactive"
	ServiceStatusHealthy   ServiceStatus = "healthy"
	ServiceStatusUnhealthy ServiceStatus = "unhealthy"
)

type NodeStatus string

// NodeStatus represents the status of a node, indicating whether it is online or offline.
const (
	NodeStatusOnline  NodeStatus = "online"
	NodeStatusOffline NodeStatus = "offline"
)

// A request to register a service in Arrowhead, allowing a node to provide its services to others.
type RegistrationRequest struct {
	Service Service `json:"service"`
	Node    Node    `json:"node"`
}

// A request to authorize a consumer to access a provider's service, allowing for controlled access to services.
type AuthRequest struct {
	ConsumerID string `json:"consumer_id"`
	ProviderID string `json:"provider_id"`
	ServiceID  string `json:"service_id"`
}

// A request to publish an event to a topic, allowing a node to notify subscribers about an event.
type EventPublishRequest struct {
	Type     string            `json:"type"`
	Topic    string            `json:"topic"`
	Payload  interface{}       `json:"payload"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// A request to subscribe to a topic, allowing a node to receive events published to that topic.
type SubscriptionRequest struct {
	Topic    string            `json:"topic"`
	Endpoint string            `json:"endpoint"`
	Filters  map[string]string `json:"filters,omitempty"`
}

// Statistics about Arrowhead.
type Metrics struct {
	TotalNodes         int64 `json:"total_nodes"`
	TotalServices      int64 `json:"total_services"`
	ActiveNodes        int64 `json:"active_nodes"`
	ActiveServices     int64 `json:"active_services"`
	TotalEvents        int64 `json:"total_events"`
	TotalSubscriptions int64 `json:"total_subscriptions"`
}

// Gateway represents an inter-cloud communication gateway for connecting different Arrowhead clouds.
type Gateway struct {
	ID              string            `json:"id" db:"id"`
	Name            string            `json:"name" db:"name"`
	Address         string            `json:"address" db:"address"`
	Port            int               `json:"port" db:"port"`
	CloudID         string            `json:"cloud_id" db:"cloud_id"`
	Certificate     string            `json:"certificate,omitempty" db:"certificate"`
	CertificateHash string            `json:"certificate_hash,omitempty" db:"certificate_hash"`
	PublicKey       string            `json:"public_key,omitempty" db:"public_key"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	Status          GatewayStatus     `json:"status" db:"status"`
	CreatedAt       time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at" db:"updated_at"`
	LastSeen        time.Time         `json:"last_seen" db:"last_seen"`
}

// GatewayTunnel represents a secure communication tunnel between two gateways.
type GatewayTunnel struct {
	ID              string         `json:"id" db:"id"`
	Name            string         `json:"name" db:"name"`
	LocalGatewayID  string         `json:"local_gateway_id" db:"local_gateway_id"`
	RemoteGatewayID string         `json:"remote_gateway_id" db:"remote_gateway_id"`
	RemoteAddress   string         `json:"remote_address" db:"remote_address"`
	RemotePort      int            `json:"remote_port" db:"remote_port"`
	Protocol        TunnelProtocol `json:"protocol" db:"protocol"`
	EncryptionType  string         `json:"encryption_type" db:"encryption_type"`
	SharedSecret    string         `json:"shared_secret,omitempty" db:"shared_secret"`
	Status          TunnelStatus   `json:"status" db:"status"`
	CreatedAt       time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at" db:"updated_at"`
	LastUsed        time.Time      `json:"last_used" db:"last_used"`
}

// RelayConnection represents a connection to a message broker for inter-cloud relay.
type RelayConnection struct {
	ID           string                `json:"id" db:"id"`
	Name         string                `json:"name" db:"name"`
	GatewayID    string                `json:"gateway_id" db:"gateway_id"`
	BrokerType   RelayBrokerType       `json:"broker_type" db:"broker_type"`
	BrokerURL    string                `json:"broker_url" db:"broker_url"`
	Username     string                `json:"username,omitempty" db:"username"`
	Password     string                `json:"password,omitempty" db:"password"`
	TLSEnabled   bool                  `json:"tls_enabled" db:"tls_enabled"`
	CertPath     string                `json:"cert_path,omitempty" db:"cert_path"`
	KeyPath      string                `json:"key_path,omitempty" db:"key_path"`
	CACertPath   string                `json:"ca_cert_path,omitempty" db:"ca_cert_path"`
	MaxRetries   int                   `json:"max_retries" db:"max_retries"`
	RetryDelay   time.Duration         `json:"retry_delay" db:"retry_delay"`
	Status       RelayConnectionStatus `json:"status" db:"status"`
	CreatedAt    time.Time             `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time             `json:"updated_at" db:"updated_at"`
	LastPingAt   time.Time             `json:"last_ping_at" db:"last_ping_at"`
	ErrorMessage string                `json:"error_message,omitempty" db:"error_message"`
}

// GatewaySession represents an active session between two gateways through a tunnel.
type GatewaySession struct {
	ID             string            `json:"id" db:"id"`
	TunnelID       string            `json:"tunnel_id" db:"tunnel_id"`
	RequesterID    string            `json:"requester_id" db:"requester_id"`
	ProviderID     string            `json:"provider_id" db:"provider_id"`
	ServiceID      string            `json:"service_id" db:"service_id"`
	SessionToken   string            `json:"session_token" db:"session_token"`
	ExpiresAt      time.Time         `json:"expires_at" db:"expires_at"`
	Status         SessionStatus     `json:"status" db:"status"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	CreatedAt      time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at" db:"updated_at"`
	LastActivityAt time.Time         `json:"last_activity_at" db:"last_activity_at"`
}

// GatewayMessage represents a message sent through the gateway relay.
type GatewayMessage struct {
	ID           string            `json:"id"`
	Type         MessageType       `json:"type"`
	SourceCloud  string            `json:"source_cloud"`
	TargetCloud  string            `json:"target_cloud"`
	ServiceName  string            `json:"service_name"`
	Payload      []byte            `json:"payload"`
	Headers      map[string]string `json:"headers,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	ExpiresAt    time.Time         `json:"expires_at"`
	Priority     MessagePriority   `json:"priority"`
	RetryCount   int               `json:"retry_count"`
	MaxRetries   int               `json:"max_retries"`
	Encrypted    bool              `json:"encrypted"`
	Signature    string            `json:"signature,omitempty"`
	SharedSecret string            `json:"shared_secret,omitempty"`
}

// Gateway-related enums and constants
type GatewayStatus string

const (
	GatewayStatusOnline      GatewayStatus = "online"
	GatewayStatusOffline     GatewayStatus = "offline"
	GatewayStatusMaintenance GatewayStatus = "maintenance"
	GatewayStatusError       GatewayStatus = "error"
)

type TunnelProtocol string

const (
	TunnelProtocolHTTPS TunnelProtocol = "https"
	TunnelProtocolMQTT  TunnelProtocol = "mqtt"
)

type TunnelStatus string

const (
	TunnelStatusActive     TunnelStatus = "active"
	TunnelStatusInactive   TunnelStatus = "inactive"
	TunnelStatusConnecting TunnelStatus = "connecting"
	TunnelStatusError      TunnelStatus = "error"
)

type RelayBrokerType string

const (
	RelayBrokerHTTP RelayBrokerType = "http"
	RelayBrokerMQTT RelayBrokerType = "mqtt"
)

type RelayConnectionStatus string

const (
	RelayConnectionStatusConnected    RelayConnectionStatus = "connected"
	RelayConnectionStatusDisconnected RelayConnectionStatus = "disconnected"
	RelayConnectionStatusConnecting   RelayConnectionStatus = "connecting"
	RelayConnectionStatusError        RelayConnectionStatus = "error"
)

type SessionStatus string

const (
	SessionStatusActive  SessionStatus = "active"
	SessionStatusExpired SessionStatus = "expired"
	SessionStatusClosed  SessionStatus = "closed"
	SessionStatusPending SessionStatus = "pending"
)

type MessageType string

const (
	MessageTypeRequest       MessageType = "request"
	MessageTypeResponse      MessageType = "response"
	MessageTypeEvent         MessageType = "event"
	MessageTypeHeartbeat     MessageType = "heartbeat"
	MessageTypeRegistration  MessageType = "registration"
	MessageTypeAuthorization MessageType = "authorization"
)

type MessagePriority string

const (
	MessagePriorityLow      MessagePriority = "low"
	MessagePriorityNormal   MessagePriority = "normal"
	MessagePriorityHigh     MessagePriority = "high"
	MessagePriorityCritical MessagePriority = "critical"
)

// Gateway-related request/response models
type GatewayRegistrationRequest struct {
	Gateway Gateway `json:"gateway"`
}

type TunnelCreateRequest struct {
	Name            string         `json:"name"`
	RemoteGatewayID string         `json:"remote_gateway_id"`
	RemoteAddress   string         `json:"remote_address"`
	RemotePort      int            `json:"remote_port"`
	Protocol        TunnelProtocol `json:"protocol"`
	EncryptionType  string         `json:"encryption_type"`
	SharedSecret    string         `json:"shared_secret,omitempty"`
}

type RelayConfigRequest struct {
	Name       string          `json:"name"`
	BrokerType RelayBrokerType `json:"broker_type"`
	BrokerURL  string          `json:"broker_url"`
	Username   string          `json:"username,omitempty"`
	Password   string          `json:"password,omitempty"`
	TLSEnabled bool            `json:"tls_enabled"`
	CertPath   string          `json:"cert_path,omitempty"`
	KeyPath    string          `json:"key_path,omitempty"`
	CACertPath string          `json:"ca_cert_path,omitempty"`
	MaxRetries int             `json:"max_retries"`
	RetryDelay time.Duration   `json:"retry_delay"`
}

type GatewayOrchestrationRequest struct {
	RequesterID   string                 `json:"requester_id"`
	ServiceName   string                 `json:"service_name"`
	TargetCloudID string                 `json:"target_cloud_id"`
	Filters       map[string]interface{} `json:"filters,omitempty"`
	Preferences   map[string]interface{} `json:"preferences,omitempty"`
}

type GatewayOrchestrationResponse struct {
	TunnelID      string          `json:"tunnel_id"`
	SessionID     string          `json:"session_id"`
	SessionToken  string          `json:"session_token"`
	Service       ServiceResponse `json:"service"`
	RemoteGateway Gateway         `json:"remote_gateway"`
	ExpiresAt     time.Time       `json:"expires_at"`
}
