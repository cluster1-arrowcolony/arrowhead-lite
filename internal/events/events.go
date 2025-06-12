package events

import (
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// Database interface for event storage operations (moved from manager.go)
type Database interface {
	CreateEvent(event *pkg.Event) error
	GetEvent(id string) (*pkg.Event, error)
	ListEvents(limit int) ([]*pkg.Event, error)
	DeleteOldEvents(before time.Time) error
	CreateSubscription(sub *pkg.Subscription) error
	GetSubscription(id string) (*pkg.Subscription, error)
	GetSubscriptionsByTopic(topic string) ([]*pkg.Subscription, error)
	UpdateSubscription(sub *pkg.Subscription) error
	DeleteSubscription(id string) error
	ListSubscriptions() ([]*pkg.Subscription, error)
	GetNode(id string) (*pkg.Node, error)
}

// NewEventManager creates a new event manager instance
func NewEventManager(db Database, logger *logrus.Logger) *EventManager {
	return newEventManager(db, logger)
}
