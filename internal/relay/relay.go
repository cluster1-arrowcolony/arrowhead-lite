package relay

import (
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Database interface for relay storage operations
type Database interface {
	CreateRelayConnection(connection *pkg.RelayConnection) error
	UpdateRelayConnection(connection *pkg.RelayConnection) error
}

// Config interface for relay configuration
type Config interface {
	// GetRelay returns relay-specific configuration
	GetRelay() RelayConfig
}

// RelayConfig holds configuration for relay operations
type RelayConfig struct {
	Enabled     bool                    `json:"enabled"`
	Connections []RelayConnectionConfig `json:"connections"`
}

// RelayConnectionConfig holds configuration for individual relay connections
type RelayConnectionConfig struct {
	Name       string `json:"name"`
	BrokerType string `json:"broker_type"`
	BrokerURL  string `json:"broker_url"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	TLSEnabled bool   `json:"tls_enabled"`
	CertPath   string `json:"cert_path,omitempty"`
	KeyPath    string `json:"key_path,omitempty"`
	CACertPath string `json:"ca_cert_path,omitempty"`
	MaxRetries int    `json:"max_retries"`
}

// NewRelayManager creates a new relay manager instance
func NewRelayManager(db Database, config Config, logger *logrus.Logger) *RelayManager {
	return newRelayManager(db, config, logger)
}
