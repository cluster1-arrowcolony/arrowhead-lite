package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/sirupsen/logrus"
)

// MQTT Relay Client implementation
type MQTTRelayClient struct {
	config    *pkg.RelayConnection
	client    mqtt.Client
	logger    *logrus.Entry
	mu        sync.RWMutex
	topics    map[string]mqtt.MessageHandler
	connected bool
}

func (mrc *MQTTRelayClient) Connect() error {
	mrc.logger.WithField("broker", mrc.config.BrokerURL).Info("Connecting to MQTT broker")

	token := mrc.client.Connect()
	if !token.WaitTimeout(30 * time.Second) {
		return fmt.Errorf("MQTT connection timeout")
	}
	if err := token.Error(); err != nil {
		return fmt.Errorf("MQTT connection failed: %w", err)
	}

	mrc.mu.Lock()
	mrc.connected = true
	mrc.mu.Unlock()

	mrc.logger.Info("Successfully connected to MQTT broker")
	return nil
}

func (mrc *MQTTRelayClient) Disconnect() error {
	mrc.logger.Info("Disconnecting from MQTT broker")

	mrc.mu.Lock()
	mrc.connected = false
	mrc.mu.Unlock()

	mrc.client.Disconnect(1000) // Wait up to 1 second for disconnect
	mrc.logger.Info("Disconnected from MQTT broker")
	return nil
}

func (mrc *MQTTRelayClient) SendMessage(message *pkg.GatewayMessage) error {
	if !mrc.IsConnected() {
		return fmt.Errorf("MQTT client not connected")
	}

	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	topic := fmt.Sprintf("arrowhead/gateway/%s/messages", message.TargetCloud)
	qos := byte(1) // At least once delivery

	mrc.logger.WithFields(logrus.Fields{
		"topic":        topic,
		"message_id":   message.ID,
		"target_cloud": message.TargetCloud,
	}).Debug("Publishing MQTT message")

	token := mrc.client.Publish(topic, qos, false, payload)
	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("MQTT publish timeout")
	}
	if err := token.Error(); err != nil {
		return fmt.Errorf("MQTT publish failed: %w", err)
	}

	mrc.logger.WithField("message_id", message.ID).Debug("Message published successfully")
	return nil
}

func (mrc *MQTTRelayClient) ReceiveMessages(ctx context.Context, handler func(*pkg.GatewayMessage) error) error {
	if !mrc.IsConnected() {
		return fmt.Errorf("MQTT client not connected")
	}

	topic := fmt.Sprintf("arrowhead/gateway/%s/messages", mrc.config.GatewayID)
	qos := byte(1)

	messageHandler := func(client mqtt.Client, msg mqtt.Message) {
		mrc.logger.WithFields(logrus.Fields{
			"topic":   msg.Topic(),
			"payload": string(msg.Payload()),
		}).Debug("Received MQTT message")

		var gatewayMessage pkg.GatewayMessage
		if err := json.Unmarshal(msg.Payload(), &gatewayMessage); err != nil {
			mrc.logger.WithError(err).Error("Failed to unmarshal gateway message")
			return
		}

		if err := handler(&gatewayMessage); err != nil {
			mrc.logger.WithError(err).Error("Failed to handle gateway message")
		}
	}

	mrc.mu.Lock()
	mrc.topics[topic] = messageHandler
	mrc.mu.Unlock()

	mrc.logger.WithField("topic", topic).Info("Subscribing to MQTT topic")

	token := mrc.client.Subscribe(topic, qos, messageHandler)
	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("MQTT subscribe timeout")
	}
	if err := token.Error(); err != nil {
		return fmt.Errorf("MQTT subscribe failed: %w", err)
	}

	mrc.logger.WithField("topic", topic).Info("Successfully subscribed to MQTT topic")

	// Wait for context cancellation
	<-ctx.Done()

	// Unsubscribe when context is done
	mrc.logger.WithField("topic", topic).Info("Unsubscribing from MQTT topic")
	unsubToken := mrc.client.Unsubscribe(topic)
	if unsubToken.WaitTimeout(5 * time.Second) {
		if err := unsubToken.Error(); err != nil {
			mrc.logger.WithError(err).Warn("Failed to unsubscribe from MQTT topic")
		}
	}

	mrc.mu.Lock()
	delete(mrc.topics, topic)
	mrc.mu.Unlock()

	return ctx.Err()
}

func (mrc *MQTTRelayClient) Ping() error {
	if !mrc.IsConnected() {
		return fmt.Errorf("MQTT client not connected")
	}

	// MQTT ping is handled automatically by the client library
	// We can check if the client is still connected
	if !mrc.client.IsConnected() {
		mrc.mu.Lock()
		mrc.connected = false
		mrc.mu.Unlock()
		return fmt.Errorf("MQTT connection lost")
	}

	return nil
}

func (mrc *MQTTRelayClient) IsConnected() bool {
	mrc.mu.RLock()
	defer mrc.mu.RUnlock()
	return mrc.connected && mrc.client.IsConnected()
}
