package database

import (
	"fmt"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
)

type Database interface {
	// Node operations
	CreateNode(node *pkg.Node) error
	GetNode(id string) (*pkg.Node, error)
	GetNodeByName(name string) (*pkg.Node, error)
	UpdateNode(node *pkg.Node) error
	DeleteNode(id string) error
	ListNodes() ([]*pkg.Node, error)

	// Service operations
	CreateService(service *pkg.Service) error
	GetService(id string) (*pkg.Service, error)
	GetServicesByNode(nodeID string) ([]*pkg.Service, error)
	GetServicesByName(name string) ([]*pkg.Service, error)
	UpdateService(service *pkg.Service) error
	DeleteService(id string) error
	ListServices() ([]*pkg.Service, error)

	// Authorization operations
	CreateAuthRule(rule *pkg.AuthRule) error
	GetAuthRule(id string) (*pkg.AuthRule, error)
	GetAuthRules(consumerID, providerID, serviceID string) ([]*pkg.AuthRule, error)
	DeleteAuthRule(id string) error
	ListAuthRules() ([]*pkg.AuthRule, error)

	// Event operations
	CreateEvent(event *pkg.Event) error
	GetEvent(id string) (*pkg.Event, error)
	ListEvents(limit int) ([]*pkg.Event, error)
	DeleteOldEvents(before time.Time) error

	// Subscription operations
	CreateSubscription(sub *pkg.Subscription) error
	GetSubscription(id string) (*pkg.Subscription, error)
	GetSubscriptionsByTopic(topic string) ([]*pkg.Subscription, error)
	UpdateSubscription(sub *pkg.Subscription) error
	DeleteSubscription(id string) error
	ListSubscriptions() ([]*pkg.Subscription, error)

	// Gateway operations
	CreateGateway(gateway *pkg.Gateway) error
	GetGateway(id string) (*pkg.Gateway, error)
	UpdateGateway(gateway *pkg.Gateway) error
	DeleteGateway(id string) error
	ListGateways() ([]*pkg.Gateway, error)

	// Gateway Tunnel operations
	CreateTunnel(tunnel *pkg.GatewayTunnel) error
	GetTunnel(id string) (*pkg.GatewayTunnel, error)
	UpdateTunnel(tunnel *pkg.GatewayTunnel) error
	DeleteTunnel(id string) error
	ListTunnelsByGateway(gatewayID string) ([]*pkg.GatewayTunnel, error)

	// Gateway Session operations
	CreateSession(session *pkg.GatewaySession) error
	GetSession(id string) (*pkg.GatewaySession, error)
	UpdateSession(session *pkg.GatewaySession) error
	DeleteSession(id string) error
	ListSessionsByTunnel(tunnelID string) ([]*pkg.GatewaySession, error)

	// Relay Connection operations
	CreateRelayConnection(connection *pkg.RelayConnection) error
	GetRelayConnection(id string) (*pkg.RelayConnection, error)
	UpdateRelayConnection(connection *pkg.RelayConnection) error
	DeleteRelayConnection(id string) error
	ListRelayConnectionsByGateway(gatewayID string) ([]*pkg.RelayConnection, error)

	// Metrics
	GetMetrics() (*pkg.Metrics, error)

	Close() error
}

// NewStorage creates database storage based on configuration
func NewStorage(dbType string, connection string) (Database, error) {
	switch dbType {
	case "postgres", "postgresql":
		return NewPostgreSQL(connection)
	case "sqlite", "sqlite3":
		return NewSQLiteDB(connection)
	default:
		return nil, fmt.Errorf("unsupported database type: %s (supported: postgres, sqlite)", dbType)
	}
}
