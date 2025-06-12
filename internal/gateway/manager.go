package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// GatewayManager manages inter-cloud communication gateways, tunnels, and sessions
type GatewayManager struct {
	mu             sync.RWMutex
	gateways       map[string]*pkg.Gateway
	tunnels        map[string]*pkg.GatewayTunnel
	sessions       map[string]*pkg.GatewaySession
	relayManager   RelayManager
	securityLayer  SecurityManager
	db             Database
	config         Config
	logger         *logrus.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	sessionCleanup chan string
}

// newGatewayManager creates a new gateway manager instance
func newGatewayManager(db Database, config Config, logger *logrus.Logger, relayManager RelayManager, securityLayer SecurityManager) *GatewayManager {
	ctx, cancel := context.WithCancel(context.Background())

	gm := &GatewayManager{
		gateways:       make(map[string]*pkg.Gateway),
		tunnels:        make(map[string]*pkg.GatewayTunnel),
		sessions:       make(map[string]*pkg.GatewaySession),
		relayManager:   relayManager,
		securityLayer:  securityLayer,
		db:             db,
		config:         config,
		logger:         logger,
		ctx:            ctx,
		cancel:         cancel,
		sessionCleanup: make(chan string, 100),
	}

	// Start background tasks
	go gm.sessionCleanupWorker()
	go gm.healthCheckWorker()

	return gm
}

// RegisterGateway registers a new gateway in the node
func (gm *GatewayManager) RegisterGateway(gateway *pkg.Gateway) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// Validate gateway
	if err := gm.validateGateway(gateway); err != nil {
		return fmt.Errorf("gateway validation failed: %w", err)
	}

	// Generate ID if not provided
	if gateway.ID == "" {
		gateway.ID = gm.generateID()
	}

	// Set timestamps
	now := time.Now()
	gateway.CreatedAt = now
	gateway.UpdatedAt = now
	gateway.LastSeen = now
	gateway.Status = pkg.GatewayStatusOnline

	// Validate and store certificate
	if gateway.Certificate != "" {
		if err := gm.securityLayer.ValidateCertificate(gateway.Certificate); err != nil {
			return fmt.Errorf("certificate validation failed: %w", err)
		}
		gateway.CertificateHash = gm.securityLayer.GetCertificateHash(gateway.Certificate)
	}

	// Store in database
	if err := gm.db.CreateGateway(gateway); err != nil {
		return fmt.Errorf("failed to store gateway in database: %w", err)
	}

	// Store in memory
	gm.gateways[gateway.ID] = gateway

	gm.logger.WithFields(logrus.Fields{
		"gateway_id":   gateway.ID,
		"gateway_name": gateway.Name,
		"cloud_id":     gateway.CloudID,
	}).Info("Gateway registered successfully")

	return nil
}

// CreateTunnel creates a new secure tunnel between gateways
func (gm *GatewayManager) CreateTunnel(localGatewayID string, request *pkg.TunnelCreateRequest) (*pkg.GatewayTunnel, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// Validate local gateway exists
	localGateway, exists := gm.gateways[localGatewayID]
	if !exists {
		return nil, fmt.Errorf("local gateway %s not found", localGatewayID)
	}

	// Validate remote gateway exists
	remoteGateway, exists := gm.gateways[request.RemoteGatewayID]
	if !exists {
		return nil, fmt.Errorf("remote gateway %s not found", request.RemoteGatewayID)
	}

	// Create tunnel
	tunnel := &pkg.GatewayTunnel{
		ID:              gm.generateID(),
		Name:            request.Name,
		LocalGatewayID:  localGatewayID,
		RemoteGatewayID: request.RemoteGatewayID,
		RemoteAddress:   request.RemoteAddress,
		RemotePort:      request.RemotePort,
		Protocol:        request.Protocol,
		EncryptionType:  request.EncryptionType,
		SharedSecret:    request.SharedSecret,
		Status:          pkg.TunnelStatusConnecting,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Establish secure connection
	if err := gm.establishTunnelConnection(tunnel, localGateway, remoteGateway); err != nil {
		return nil, fmt.Errorf("failed to establish tunnel connection: %w", err)
	}

	// Store in database
	if err := gm.db.CreateTunnel(tunnel); err != nil {
		return nil, fmt.Errorf("failed to store tunnel in database: %w", err)
	}

	// Store in memory
	gm.tunnels[tunnel.ID] = tunnel

	gm.logger.WithFields(logrus.Fields{
		"tunnel_id":      tunnel.ID,
		"local_gateway":  localGatewayID,
		"remote_gateway": request.RemoteGatewayID,
		"protocol":       request.Protocol,
	}).Info("Tunnel created successfully")

	return tunnel, nil
}

// CreateSession creates a new gateway session for inter-cloud service access
func (gm *GatewayManager) CreateSession(tunnelID, requesterID, providerID, serviceID string, duration time.Duration) (*pkg.GatewaySession, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// Validate tunnel exists and is active
	tunnel, exists := gm.tunnels[tunnelID]
	if !exists {
		return nil, fmt.Errorf("tunnel %s not found", tunnelID)
	}
	if tunnel.Status != pkg.TunnelStatusActive {
		return nil, fmt.Errorf("tunnel %s is not active (status: %s)", tunnelID, tunnel.Status)
	}

	// Generate session token
	sessionToken, err := gm.generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Create session
	session := &pkg.GatewaySession{
		ID:             gm.generateID(),
		TunnelID:       tunnelID,
		RequesterID:    requesterID,
		ProviderID:     providerID,
		ServiceID:      serviceID,
		SessionToken:   sessionToken,
		ExpiresAt:      time.Now().Add(duration),
		Status:         pkg.SessionStatusActive,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		LastActivityAt: time.Now(),
	}

	// Store in database
	if err := gm.db.CreateSession(session); err != nil {
		return nil, fmt.Errorf("failed to store session in database: %w", err)
	}

	// Store in memory
	gm.sessions[session.ID] = session

	// Schedule cleanup
	go func() {
		time.Sleep(duration)
		gm.sessionCleanup <- session.ID
	}()

	gm.logger.WithFields(logrus.Fields{
		"session_id":   session.ID,
		"tunnel_id":    tunnelID,
		"requester_id": requesterID,
		"provider_id":  providerID,
		"service_id":   serviceID,
		"expires_at":   session.ExpiresAt,
	}).Info("Gateway session created")

	return session, nil
}

// RouteMessage routes a message through the appropriate gateway tunnel
func (gm *GatewayManager) RouteMessage(message *pkg.GatewayMessage) error {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	// Find appropriate tunnel for target cloud
	var tunnel *pkg.GatewayTunnel
	for _, t := range gm.tunnels {
		if gm.gateways[t.RemoteGatewayID].CloudID == message.TargetCloud && t.Status == pkg.TunnelStatusActive {
			tunnel = t
			break
		}
	}

	if tunnel == nil {
		return fmt.Errorf("no active tunnel found for target cloud %s", message.TargetCloud)
	}

	// Encrypt message if required
	if message.Encrypted {
		if err := gm.securityLayer.EncryptMessage(message); err != nil {
			return fmt.Errorf("failed to encrypt message: %w", err)
		}
	}

	// Sign message
	if err := gm.securityLayer.SignMessage(message); err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	// Route through relay manager
	if err := gm.relayManager.SendMessage(tunnel.ID, message); err != nil {
		return fmt.Errorf("failed to send message through relay: %w", err)
	}

	// Update tunnel last used
	tunnel.LastUsed = time.Now()
	tunnel.UpdatedAt = time.Now()

	gm.logger.WithFields(logrus.Fields{
		"message_id":   message.ID,
		"tunnel_id":    tunnel.ID,
		"source_cloud": message.SourceCloud,
		"target_cloud": message.TargetCloud,
		"service_name": message.ServiceName,
	}).Debug("Message routed through gateway")

	return nil
}

// ValidateSession validates a gateway session token
func (gm *GatewayManager) ValidateSession(sessionToken string) (*pkg.GatewaySession, error) {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	for _, session := range gm.sessions {
		if session.SessionToken == sessionToken {
			if session.Status != pkg.SessionStatusActive {
				return nil, fmt.Errorf("session is not active (status: %s)", session.Status)
			}
			if time.Now().After(session.ExpiresAt) {
				return nil, fmt.Errorf("session has expired")
			}

			// Update last activity
			session.LastActivityAt = time.Now()
			session.UpdatedAt = time.Now()

			return session, nil
		}
	}

	return nil, fmt.Errorf("invalid session token")
}

// GetGateway retrieves a gateway by ID
func (gm *GatewayManager) GetGateway(id string) (*pkg.Gateway, error) {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	gateway, exists := gm.gateways[id]
	if !exists {
		return nil, fmt.Errorf("gateway %s not found", id)
	}

	return gateway, nil
}

// ListGateways returns all registered gateways
func (gm *GatewayManager) ListGateways() []*pkg.Gateway {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	gateways := make([]*pkg.Gateway, 0, len(gm.gateways))
	for _, gateway := range gm.gateways {
		gateways = append(gateways, gateway)
	}

	return gateways
}

// ListTunnels returns all tunnels for a gateway
func (gm *GatewayManager) ListTunnels(gatewayID string) []*pkg.GatewayTunnel {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	tunnels := make([]*pkg.GatewayTunnel, 0)
	for _, tunnel := range gm.tunnels {
		if tunnel.LocalGatewayID == gatewayID || tunnel.RemoteGatewayID == gatewayID {
			tunnels = append(tunnels, tunnel)
		}
	}

	return tunnels
}

// CloseSession closes an active gateway session
func (gm *GatewayManager) CloseSession(sessionID string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	session, exists := gm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.Status = pkg.SessionStatusClosed
	session.UpdatedAt = time.Now()

	if err := gm.db.UpdateSession(session); err != nil {
		gm.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to update session in database")
	}

	gm.logger.WithField("session_id", sessionID).Info("Gateway session closed")

	return nil
}

// Shutdown gracefully shuts down the gateway manager
func (gm *GatewayManager) Shutdown() error {
	gm.logger.Info("Shutting down Gateway Manager")

	gm.cancel()

	// Close all active sessions
	gm.mu.Lock()
	for sessionID := range gm.sessions {
		if err := gm.CloseSession(sessionID); err != nil {
			gm.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to close session during shutdown")
		}
	}
	gm.mu.Unlock()

	return nil
}

// Private methods

func (gm *GatewayManager) validateGateway(gateway *pkg.Gateway) error {
	if gateway.Name == "" {
		return fmt.Errorf("gateway name is required")
	}
	if gateway.Address == "" {
		return fmt.Errorf("gateway address is required")
	}
	if gateway.Port <= 0 || gateway.Port > 65535 {
		return fmt.Errorf("invalid gateway port: %d", gateway.Port)
	}
	if gateway.CloudID == "" {
		return fmt.Errorf("cloud ID is required")
	}
	return nil
}

func (gm *GatewayManager) generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (gm *GatewayManager) generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (gm *GatewayManager) establishTunnelConnection(tunnel *pkg.GatewayTunnel, localGateway, remoteGateway *pkg.Gateway) error {
	// Validate certificates for secure connection
	if err := gm.securityLayer.ValidateTunnelSecurity(tunnel, localGateway, remoteGateway); err != nil {
		return fmt.Errorf("tunnel security validation failed: %w", err)
	}

	// Test connection based on protocol
	switch tunnel.Protocol {
	case pkg.TunnelProtocolHTTPS:
		if err := gm.testHTTPSConnection(tunnel); err != nil {
			return fmt.Errorf("HTTPS connection test failed: %w", err)
		}
	case pkg.TunnelProtocolMQTT:
		if err := gm.testMQTTConnection(tunnel); err != nil {
			return fmt.Errorf("MQTT connection test failed: %w", err)
		}
	default:
		return fmt.Errorf("unsupported tunnel protocol: %s", tunnel.Protocol)
	}

	tunnel.Status = pkg.TunnelStatusActive
	return nil
}

func (gm *GatewayManager) testHTTPSConnection(tunnel *pkg.GatewayTunnel) error {
	gm.logger.WithField("tunnel_id", tunnel.ID).Debug("Testing HTTPS tunnel connection")

	// Basic connectivity test - would typically include:
	// 1. TLS handshake validation
	// 2. Certificate verification
	// 3. Protocol compatibility check
	// 4. Timeout and retry logic

	// For now, simulate basic validation
	if tunnel.RemoteAddress == "" {
		return fmt.Errorf("remote address not specified")
	}

	if tunnel.RemotePort <= 0 || tunnel.RemotePort > 65535 {
		return fmt.Errorf("invalid remote port: %d", tunnel.RemotePort)
	}

	// In a real implementation, this would establish an actual HTTPS connection
	// and verify the remote gateway is reachable and responds correctly

	return nil
}

func (gm *GatewayManager) testMQTTConnection(tunnel *pkg.GatewayTunnel) error {
	gm.logger.WithField("tunnel_id", tunnel.ID).Debug("Testing MQTT tunnel connection")

	// Basic MQTT connectivity test - would typically include:
	// 1. MQTT broker connection
	// 2. Authentication validation
	// 3. Topic publish/subscribe permissions
	// 4. QoS compatibility check

	// For now, simulate basic validation
	if tunnel.RemoteAddress == "" {
		return fmt.Errorf("remote address not specified")
	}

	if tunnel.RemotePort <= 0 || tunnel.RemotePort > 65535 {
		return fmt.Errorf("invalid remote port: %d", tunnel.RemotePort)
	}

	// In a real implementation, this would:
	// - Connect to the MQTT broker
	// - Verify authentication credentials
	// - Test basic pub/sub functionality
	// - Validate QoS levels and retain policies

	return nil
}

func (gm *GatewayManager) sessionCleanupWorker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-gm.ctx.Done():
			return
		case sessionID := <-gm.sessionCleanup:
			gm.cleanupExpiredSession(sessionID)
		case <-ticker.C:
			gm.cleanupExpiredSessions()
		}
	}
}

func (gm *GatewayManager) cleanupExpiredSession(sessionID string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	session, exists := gm.sessions[sessionID]
	if !exists {
		return
	}

	if time.Now().After(session.ExpiresAt) && session.Status == pkg.SessionStatusActive {
		session.Status = pkg.SessionStatusExpired
		session.UpdatedAt = time.Now()

		if err := gm.db.UpdateSession(session); err != nil {
			gm.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to update expired session in database")
		}

		gm.logger.WithField("session_id", sessionID).Info("Gateway session expired and cleaned up")
	}
}

func (gm *GatewayManager) cleanupExpiredSessions() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	now := time.Now()
	for sessionID, session := range gm.sessions {
		if now.After(session.ExpiresAt) && session.Status == pkg.SessionStatusActive {
			session.Status = pkg.SessionStatusExpired
			session.UpdatedAt = now

			if err := gm.db.UpdateSession(session); err != nil {
				gm.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to update expired session in database")
			}
		}
	}
}

func (gm *GatewayManager) healthCheckWorker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-gm.ctx.Done():
			return
		case <-ticker.C:
			gm.performHealthChecks()
		}
	}
}

func (gm *GatewayManager) performHealthChecks() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	now := time.Now()
	healthCheckTimeout := 2 * time.Minute

	// Check gateway health
	for gatewayID, gateway := range gm.gateways {
		if now.Sub(gateway.LastSeen) > healthCheckTimeout {
			gateway.Status = pkg.GatewayStatusOffline
			gateway.UpdatedAt = now

			if err := gm.db.UpdateGateway(gateway); err != nil {
				gm.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Failed to update gateway status in database")
			}
		}
	}

	// Check tunnel health
	for tunnelID, tunnel := range gm.tunnels {
		if now.Sub(tunnel.LastUsed) > 5*time.Minute && tunnel.Status == pkg.TunnelStatusActive {
			// Perform tunnel health check
			if err := gm.performTunnelHealthCheck(tunnel); err != nil {
				tunnel.Status = pkg.TunnelStatusError
				tunnel.UpdatedAt = now

				if err := gm.db.UpdateTunnel(tunnel); err != nil {
					gm.logger.WithError(err).WithField("tunnel_id", tunnelID).Error("Failed to update tunnel status in database")
				}
			}
		}
	}
}

func (gm *GatewayManager) performTunnelHealthCheck(tunnel *pkg.GatewayTunnel) error {
	gm.logger.WithField("tunnel_id", tunnel.ID).Debug("Performing tunnel health check")

	// Health check implementation based on tunnel protocol
	switch tunnel.Protocol {
	case pkg.TunnelProtocolHTTPS:
		// For HTTPS tunnels, perform a lightweight health check
		if tunnel.RemoteAddress == "" {
			return fmt.Errorf("tunnel has no remote address configured")
		}

		// In a real implementation, this would:
		// - Send an HTTP HEAD request to a health endpoint
		// - Verify SSL/TLS certificate validity
		// - Check response time and status

		gm.logger.WithField("tunnel_id", tunnel.ID).Debug("HTTPS tunnel health check completed")

	case pkg.TunnelProtocolMQTT:
		// For MQTT tunnels, perform broker connectivity check
		if tunnel.RemoteAddress == "" {
			return fmt.Errorf("tunnel has no remote address configured")
		}

		// In a real implementation, this would:
		// - Test MQTT broker connectivity
		// - Verify authentication is still valid
		// - Check topic access permissions

		gm.logger.WithField("tunnel_id", tunnel.ID).Debug("MQTT tunnel health check completed")

	default:
		return fmt.Errorf("unsupported tunnel protocol for health check: %s", tunnel.Protocol)
	}

	return nil
}
