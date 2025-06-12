package relay

import (
	"context"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
)

// Interface for different message broker implementations
type RelayClient interface {
	Connect() error
	Disconnect() error
	SendMessage(message *pkg.GatewayMessage) error
	ReceiveMessages(ctx context.Context, handler func(*pkg.GatewayMessage) error) error
	Ping() error
	IsConnected() bool
}

// A message to be delivered through the relay
type MessageDelivery struct {
	TunnelID   string
	Message    *pkg.GatewayMessage
	Retries    int
	MaxRetries int
}
