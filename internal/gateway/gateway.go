package gateway

import (
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Database interface for gateway storage operations (moved from manager.go)
type Database interface {
	CreateGateway(gateway *pkg.Gateway) error
	UpdateGateway(gateway *pkg.Gateway) error
	CreateTunnel(tunnel *pkg.GatewayTunnel) error
	UpdateTunnel(tunnel *pkg.GatewayTunnel) error
	CreateSession(session *pkg.GatewaySession) error
	UpdateSession(session *pkg.GatewaySession) error
}

// Config interface for gateway configuration (moved from manager.go)
type Config interface {
	GetGateway() *GatewayConfig
}

// RelayManager interface for message relay operations (moved from manager.go)
type RelayManager interface {
	SendMessage(tunnelID string, message *pkg.GatewayMessage) error
}

// GatewayConfig represents gateway configuration
type GatewayConfig struct {
	Enabled         bool
	CloudID         string
	CertificateFile string
	PrivateKeyFile  string
	TrustStore      string
	TrustAnchors    []TrustAnchorCfg
}

// TrustAnchorCfg represents trust anchor configuration
type TrustAnchorCfg struct {
	CloudID     string
	Certificate string
}

// SecurityManager interface for gateway security operations (moved from manager.go)
type SecurityManager interface {
	ValidateCertificate(certificatePEM string) error
	GetCertificateHash(certificatePEM string) string
	EncryptMessage(message *pkg.GatewayMessage) error
	SignMessage(message *pkg.GatewayMessage) error
	ValidateTunnelSecurity(tunnel *pkg.GatewayTunnel, localGateway, remoteGateway *pkg.Gateway) error
}

// NewGatewayManager creates a new gateway manager instance
func NewGatewayManager(db Database, config Config, logger *logrus.Logger, relayManager RelayManager, securityLayer SecurityManager) *GatewayManager {
	return newGatewayManager(db, config, logger, relayManager, securityLayer)
}

// NewGatewaySecurityManager creates a new gateway security manager instance
func NewGatewaySecurityManager(config Config, logger *logrus.Logger) (*GatewaySecurityManager, error) {
	return newGatewaySecurityManager(config, logger)
}
