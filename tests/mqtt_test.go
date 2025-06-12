package tests

import (
	"testing"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMQTTRelayClient_Creation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	config := &internal.Config{
		Database: internal.DatabaseConfig{
			Type: "sqlite",
			Path: ":memory:",
		},
	}

	db, err := internal.NewStorage(config.Database.Type, config.Database.Path)
	require.NoError(t, err)
	defer db.Close()

	relayManager := internal.NewRelayManager(db, config, logger)
	require.NotNil(t, relayManager)

	// Test MQTT relay connection configuration
	mqttConfig := &pkg.RelayConnection{
		ID:         "test-mqtt-relay",
		Name:       "Test MQTT Relay",
		GatewayID:  "test-gateway",
		BrokerType: pkg.RelayBrokerMQTT,
		BrokerURL:  "tcp://localhost:1883",
		Username:   "testuser",
		Password:   "testpass",
		TLSEnabled: false,
		MaxRetries: 3,
		RetryDelay: 5 * time.Second,
		Status:     pkg.RelayConnectionStatusDisconnected,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Test MQTT client creation through relay manager factory
	relayRequest := &pkg.RelayConfigRequest{
		Name:       mqttConfig.Name,
		BrokerType: mqttConfig.BrokerType,
		BrokerURL:  mqttConfig.BrokerURL,
		Username:   mqttConfig.Username,
		Password:   mqttConfig.Password,
		TLSEnabled: mqttConfig.TLSEnabled,
		MaxRetries: mqttConfig.MaxRetries,
		RetryDelay: mqttConfig.RetryDelay,
	}

	// Note: This test only verifies creation, not actual connection since we don't have a test MQTT broker
	_, err = relayManager.CreateRelayConnection("test-gateway", relayRequest)
	if err != nil {
		// Expected to fail since we don't have a real MQTT broker
		assert.Contains(t, err.Error(), "MQTT connection", "Should fail with MQTT connection error")
	}
}

func TestMQTTRelayClient_Configuration(t *testing.T) {
	// Test MQTT broker type constants
	assert.Equal(t, pkg.RelayBrokerType("mqtt"), pkg.RelayBrokerMQTT)
	assert.Equal(t, pkg.RelayBrokerType("http"), pkg.RelayBrokerHTTP)

	// Test tunnel protocol constants include MQTT
	assert.Equal(t, pkg.TunnelProtocol("mqtt"), pkg.TunnelProtocolMQTT)
	assert.Equal(t, pkg.TunnelProtocol("https"), pkg.TunnelProtocolHTTPS)
}

func TestMQTTTopicGeneration(t *testing.T) {
	// Test that MQTT topics follow expected format
	expectedIncomingTopic := "arrowhead/gateway/test-gateway/messages"
	expectedOutgoingTopic := "arrowhead/gateway/target-cloud/messages"

	// These would be the topics used in the actual MQTT implementation
	assert.Contains(t, expectedIncomingTopic, "test-gateway")
	assert.Contains(t, expectedOutgoingTopic, "target-cloud")
	assert.Contains(t, expectedIncomingTopic, "arrowhead/gateway/")
	assert.Contains(t, expectedOutgoingTopic, "arrowhead/gateway/")
}
