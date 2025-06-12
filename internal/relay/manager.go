package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/sirupsen/logrus"
)

// Manages message relay connections for inter-cloud communication
type RelayManager struct {
	mu           sync.RWMutex
	connections  map[string]*RelayConnection
	db           Database
	config       Config
	logger       *logrus.Logger
	ctx          context.Context
	cancel       context.CancelFunc
	messageQueue chan *MessageDelivery
}

// An active connection to a message broker
type RelayConnection struct {
	config      *pkg.RelayConnection
	client      RelayClient
	isConnected bool
	lastPing    time.Time
	errorCount  int
	mu          sync.RWMutex
}

// Create a new relay manager instance
func newRelayManager(db Database, config Config, logger *logrus.Logger) *RelayManager {
	ctx, cancel := context.WithCancel(context.Background())

	rm := &RelayManager{
		connections:  make(map[string]*RelayConnection),
		db:           db,
		config:       config,
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		messageQueue: make(chan *MessageDelivery, 1000),
	}

	// Start background workers
	go rm.messageDeliveryWorker()
	go rm.connectionHealthWorker()

	return rm
}

// Create a new relay connection
func (rm *RelayManager) CreateRelayConnection(gatewayID string, request *pkg.RelayConfigRequest) (*pkg.RelayConnection, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Validate request
	if err := rm.validateRelayConfig(request); err != nil {
		return nil, fmt.Errorf("relay config validation failed: %w", err)
	}

	// Create relay connection config
	relayConfig := &pkg.RelayConnection{
		ID:         rm.generateID(),
		Name:       request.Name,
		GatewayID:  gatewayID,
		BrokerType: request.BrokerType,
		BrokerURL:  request.BrokerURL,
		Username:   request.Username,
		Password:   request.Password,
		TLSEnabled: request.TLSEnabled,
		CertPath:   request.CertPath,
		KeyPath:    request.KeyPath,
		CACertPath: request.CACertPath,
		MaxRetries: request.MaxRetries,
		RetryDelay: request.RetryDelay,
		Status:     pkg.RelayConnectionStatusConnecting,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Create relay client based on broker type
	client, err := rm.createRelayClient(relayConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create relay client: %w", err)
	}

	// Test connection
	if err := client.Connect(); err != nil {
		relayConfig.Status = pkg.RelayConnectionStatusError
		relayConfig.ErrorMessage = err.Error()
		return nil, fmt.Errorf("failed to connect to relay broker: %w", err)
	}

	relayConfig.Status = pkg.RelayConnectionStatusConnected
	relayConfig.LastPingAt = time.Now()

	// Store in database
	if err := rm.db.CreateRelayConnection(relayConfig); err != nil {
		client.Disconnect()
		return nil, fmt.Errorf("failed to store relay connection in database: %w", err)
	}

	// Store in memory
	rm.connections[relayConfig.ID] = &RelayConnection{
		config:      relayConfig,
		client:      client,
		isConnected: true,
		lastPing:    time.Now(),
	}

	rm.logger.WithFields(logrus.Fields{
		"connection_id": relayConfig.ID,
		"gateway_id":    gatewayID,
		"broker_type":   request.BrokerType,
		"broker_url":    request.BrokerURL,
	}).Info("Relay connection created successfully")

	return relayConfig, nil
}

// Send a message through the specified tunnel's relay connection
func (rm *RelayManager) SendMessage(
	tunnelID string,
	message *pkg.GatewayMessage,
) error {
	// Queue message for delivery
	delivery := &MessageDelivery{
		TunnelID:   tunnelID,
		Message:    message,
		Retries:    0,
		MaxRetries: 3,
	}

	select {
	case rm.messageQueue <- delivery:
		return nil
	default:
		return fmt.Errorf("message queue is full")
	}
}

// Retrieve a relay connection by ID
func (rm *RelayManager) GetRelayConnection(id string) (*pkg.RelayConnection, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	connection, exists := rm.connections[id]
	if !exists {
		return nil, fmt.Errorf("relay connection %s not found", id)
	}

	return connection.config, nil
}

// Return all relay connections for a gateway
func (rm *RelayManager) ListRelayConnections(gatewayID string) []*pkg.RelayConnection {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	connections := make([]*pkg.RelayConnection, 0)
	for _, conn := range rm.connections {
		if conn.config.GatewayID == gatewayID {
			connections = append(connections, conn.config)
		}
	}

	return connections
}

// Close and removes a relay connection
func (rm *RelayManager) CloseRelayConnection(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	connection, exists := rm.connections[id]
	if !exists {
		return fmt.Errorf("relay connection %s not found", id)
	}

	// Close the client connection
	if err := connection.client.Disconnect(); err != nil {
		rm.logger.WithError(err).WithField("connection_id", id).Error("Failed to disconnect relay client")
	}

	// Update status in database
	connection.config.Status = pkg.RelayConnectionStatusDisconnected
	connection.config.UpdatedAt = time.Now()

	if err := rm.db.UpdateRelayConnection(connection.config); err != nil {
		rm.logger.WithError(err).WithField("connection_id", id).Error("Failed to update relay connection status in database")
	}

	// Remove from memory
	delete(rm.connections, id)

	rm.logger.WithField("connection_id", id).Info("Relay connection closed")

	return nil
}

// Gracefully shut down the relay manager
func (rm *RelayManager) Shutdown() error {
	rm.logger.Info("Shutting down Relay Manager")

	rm.cancel()

	// Close all connections
	rm.mu.Lock()
	for id := range rm.connections {
		if err := rm.CloseRelayConnection(id); err != nil {
			rm.logger.WithError(err).WithField("connection_id", id).Error("Failed to close relay connection during shutdown")
		}
	}
	rm.mu.Unlock()

	return nil
}

// Private methods
func (rm *RelayManager) validateRelayConfig(request *pkg.RelayConfigRequest) error {
	if request.Name == "" {
		return fmt.Errorf("relay connection name is required")
	}
	if request.BrokerURL == "" {
		return fmt.Errorf("broker URL is required")
	}
	if _, err := url.Parse(request.BrokerURL); err != nil {
		return fmt.Errorf("invalid broker URL: %w", err)
	}
	if request.MaxRetries < 0 {
		return fmt.Errorf("max retries cannot be negative")
	}
	if request.RetryDelay < 0 {
		return fmt.Errorf("retry delay cannot be negative")
	}
	return nil
}

func (rm *RelayManager) generateID() string {
	// Implementation similar to GatewayManager.generateID()
	return fmt.Sprintf("relay-%d", time.Now().UnixNano())
}

func (rm *RelayManager) createRelayClient(config *pkg.RelayConnection) (RelayClient, error) {
	switch config.BrokerType {
	case pkg.RelayBrokerHTTP:
		return rm.createHTTPClient(config)
	case pkg.RelayBrokerMQTT:
		return rm.createMQTTClient(config)
	default:
		return nil, fmt.Errorf("unsupported broker type: %s", config.BrokerType)
	}
}

func (rm *RelayManager) createHTTPClient(config *pkg.RelayConnection) (RelayClient, error) {
	var transport *http.Transport

	if config.TLSEnabled {
		tlsConfig, err := rm.createTLSConfig(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		transport = &http.Transport{TLSClientConfig: tlsConfig}
	} else {
		transport = &http.Transport{}
	}

	return &HTTPRelayClient{
		config: config,
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		logger: rm.logger,
	}, nil
}

func (rm *RelayManager) createMQTTClient(config *pkg.RelayConnection) (RelayClient, error) {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(config.BrokerURL)
	opts.SetClientID(fmt.Sprintf("arrowhead-gateway-%s", config.GatewayID))
	opts.SetCleanSession(true)
	opts.SetAutoReconnect(true)
	opts.SetConnectRetryInterval(time.Duration(config.RetryDelay))
	opts.SetMaxReconnectInterval(60 * time.Second)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	opts.SetConnectTimeout(30 * time.Second)

	if config.Username != "" {
		opts.SetUsername(config.Username)
	}
	if config.Password != "" {
		opts.SetPassword(config.Password)
	}

	if config.TLSEnabled {
		tlsConfig, err := rm.createTLSConfig(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		opts.SetTLSConfig(tlsConfig)
	}

	client := &MQTTRelayClient{
		config: config,
		client: mqtt.NewClient(opts),
		logger: rm.logger.WithField("component", "mqtt_relay"),
		topics: make(map[string]mqtt.MessageHandler),
	}

	// Set connection lost handler
	opts.SetConnectionLostHandler(func(c mqtt.Client, err error) {
		client.logger.WithError(err).Warn("MQTT connection lost")
	})

	// Set reconnect handler
	opts.SetOnConnectHandler(func(c mqtt.Client) {
		client.logger.Info("MQTT client connected/reconnected")
	})

	return client, nil
}

func (rm *RelayManager) createTLSConfig(config *pkg.RelayConnection) (*tls.Config, error) {
	tlsConfig := &tls.Config{}

	if config.CertPath != "" && config.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if specified
	if config.CACertPath != "" {
		caCert, err := ioutil.ReadFile(config.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

func (rm *RelayManager) messageDeliveryWorker() {
	for {
		select {
		case <-rm.ctx.Done():
			return
		case delivery := <-rm.messageQueue:
			rm.deliverMessage(delivery)
		}
	}
}

func (rm *RelayManager) deliverMessage(delivery *MessageDelivery) {
	rm.mu.RLock()

	// Find appropriate relay connection for tunnel
	var relayConn *RelayConnection
	for _, conn := range rm.connections {
		// Logic to determine which connection to use for the tunnel
		if conn.isConnected && conn.config.Status == pkg.RelayConnectionStatusConnected {
			relayConn = conn
			break
		}
	}
	rm.mu.RUnlock()

	if relayConn == nil {
		rm.logger.WithField("tunnel_id", delivery.TunnelID).Error("No available relay connection for message delivery")
		return
	}

	// Attempt to send message
	if err := relayConn.client.SendMessage(delivery.Message); err != nil {
		rm.logger.WithError(err).WithFields(logrus.Fields{
			"message_id": delivery.Message.ID,
			"tunnel_id":  delivery.TunnelID,
			"retry":      delivery.Retries,
		}).Error("Failed to send message through relay")

		// Retry if within limit
		if delivery.Retries < delivery.MaxRetries {
			delivery.Retries++
			time.Sleep(2 * time.Second) // Basic retry delay
			select {
			case rm.messageQueue <- delivery:
			default:
				rm.logger.WithField("message_id", delivery.Message.ID).Error("Failed to requeue message for retry")
			}
		}
		return
	}

	rm.logger.WithFields(logrus.Fields{
		"message_id":    delivery.Message.ID,
		"tunnel_id":     delivery.TunnelID,
		"connection_id": relayConn.config.ID,
	}).Debug("Message delivered successfully through relay")
}

func (rm *RelayManager) connectionHealthWorker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.performHealthChecks()
		}
	}
}

func (rm *RelayManager) performHealthChecks() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for id, conn := range rm.connections {
		conn.mu.Lock()

		// Perform ping/health check
		if err := conn.client.Ping(); err != nil {
			conn.errorCount++
			conn.config.ErrorMessage = err.Error()

			if conn.errorCount >= 3 {
				conn.config.Status = pkg.RelayConnectionStatusError
				conn.isConnected = false
			}

			rm.logger.WithError(err).WithFields(logrus.Fields{
				"connection_id": id,
				"error_count":   conn.errorCount,
			}).Warn("Relay connection health check failed")
		} else {
			conn.errorCount = 0
			conn.config.ErrorMessage = ""
			conn.config.Status = pkg.RelayConnectionStatusConnected
			conn.config.LastPingAt = time.Now()
			conn.lastPing = time.Now()
			conn.isConnected = true
		}

		conn.config.UpdatedAt = time.Now()
		conn.mu.Unlock()

		// Update database
		if err := rm.db.UpdateRelayConnection(conn.config); err != nil {
			rm.logger.WithError(err).WithField("connection_id", id).Error("Failed to update relay connection in database")
		}
	}
}
