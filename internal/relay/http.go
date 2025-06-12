package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Implements HTTP-based relay communication
type HTTPRelayClient struct {
	config *pkg.RelayConnection
	client *http.Client
	logger *logrus.Logger
}

func (hrc *HTTPRelayClient) Connect() error {
	// Test connection with a simple request
	resp, err := hrc.client.Get(hrc.config.BrokerURL + "/health")
	if err != nil {
		return fmt.Errorf("failed to connect to HTTP broker: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP broker returned error status: %d", resp.StatusCode)
	}

	return nil
}

func (hrc *HTTPRelayClient) Disconnect() error {
	// HTTP client doesn't need explicit disconnection
	return nil
}

func (hrc *HTTPRelayClient) SendMessage(message *pkg.GatewayMessage) error {
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	resp, err := hrc.client.Post(
		hrc.config.BrokerURL+"/messages",
		"application/json",
		strings.NewReader(string(messageJSON)),
	)
	if err != nil {
		return fmt.Errorf("failed to send HTTP message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP broker returned error status: %d", resp.StatusCode)
	}

	return nil
}

func (hrc *HTTPRelayClient) ReceiveMessages(ctx context.Context, handler func(*pkg.GatewayMessage) error) error {
	// HTTP polling implementation with 5-second intervals
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	hrc.logger.Debug("Starting HTTP message polling")

	for {
		select {
		case <-ctx.Done():
			hrc.logger.Debug("HTTP message polling stopped due to context cancellation")
			return ctx.Err()
		case <-ticker.C:
			if err := hrc.pollForMessages(handler); err != nil {
				hrc.logger.WithError(err).Error("Failed to poll for messages")
				// Continue polling despite errors
			}
		}
	}
}

func (hrc *HTTPRelayClient) pollForMessages(handler func(*pkg.GatewayMessage) error) error {
	resp, err := hrc.client.Get(hrc.config.BrokerURL + "/messages")
	if err != nil {
		return fmt.Errorf("failed to poll messages: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		// No messages available, this is normal
		return nil
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("message polling returned error status: %d", resp.StatusCode)
	}

	// Parse response - expecting either single message or array of messages
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Try to parse as array of messages first
	var messages []*pkg.GatewayMessage
	if err := json.Unmarshal(body, &messages); err != nil {
		// If that fails, try to parse as single message
		var message pkg.GatewayMessage
		if err := json.Unmarshal(body, &message); err != nil {
			return fmt.Errorf("failed to parse message response: %w", err)
		}
		messages = []*pkg.GatewayMessage{&message}
	}

	// Process each message through the handler
	for _, message := range messages {
		if err := handler(message); err != nil {
			hrc.logger.WithError(err).WithField("message_id", message.ID).Error("Failed to handle received message")
			// Continue processing other messages despite handler errors
		} else {
			hrc.logger.WithField("message_id", message.ID).Debug("Successfully processed received message")
		}
	}

	return nil
}

func (hrc *HTTPRelayClient) Ping() error {
	resp, err := hrc.client.Get(hrc.config.BrokerURL + "/ping")
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ping returned error status: %d", resp.StatusCode)
	}

	return nil
}

func (hrc *HTTPRelayClient) IsConnected() bool {
	return hrc.Ping() == nil
}
