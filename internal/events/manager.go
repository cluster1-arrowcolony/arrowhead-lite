package events

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type EventManager struct {
	db           Database
	logger       *logrus.Logger
	subscribers  map[string][]*Subscriber
	mutex        sync.RWMutex
	eventChannel chan *pkg.Event
	ctx          context.Context
	cancel       context.CancelFunc
	closed       bool
}

func newEventManager(db Database, logger *logrus.Logger) *EventManager {
	ctx, cancel := context.WithCancel(context.Background())

	em := &EventManager{
		db:           db,
		logger:       logger,
		subscribers:  make(map[string][]*Subscriber),
		eventChannel: make(chan *pkg.Event, 1000),
		ctx:          ctx,
		cancel:       cancel,
	}

	go em.eventProcessor()
	go em.cleanupInactiveSubscribers()

	return em
}

// PublishEvent publishes an event to the event node
func (em *EventManager) PublishEvent(req *pkg.EventPublishRequest, publisherID string) (*pkg.Event, error) {
	payload, err := json.Marshal(req.Payload)
	if err != nil {
		em.logger.WithError(err).Error("Failed to marshal event payload")
		return nil, pkg.BadRequestError("Invalid event payload")
	}

	event := &pkg.Event{
		ID:          uuid.New().String(),
		Type:        req.Type,
		Topic:       req.Topic,
		PublisherID: publisherID,
		Payload:     payload,
		Metadata:    req.Metadata,
		CreatedAt:   time.Now(),
	}

	if err := em.db.CreateEvent(event); err != nil {
		em.logger.WithError(err).Error("Failed to store event")
		return nil, pkg.DatabaseError(err)
	}

	// Check if the event manager is closed
	em.mutex.RLock()
	if em.closed {
		em.mutex.RUnlock()
		em.logger.Warn("Event manager closed, cannot publish event")
		return event, nil
	}
	em.mutex.RUnlock()

	select {
	case em.eventChannel <- event:
	default:
		em.logger.Warn("Event channel full, dropping event")
	}

	em.logger.WithFields(logrus.Fields{
		"event_id":     event.ID,
		"topic":        event.Topic,
		"type":         event.Type,
		"publisher_id": event.PublisherID,
	}).Info("Event published")

	return event, nil
}

// Subscribe creates a new subscription for events
func (em *EventManager) Subscribe(req *pkg.SubscriptionRequest, subscriberID string) (*pkg.Subscription, error) {
	node, err := em.db.GetNode(subscriberID)
	if err != nil {
		em.logger.WithError(err).Error("Failed to get subscriber node")
		return nil, pkg.DatabaseError(err)
	}

	if node == nil {
		return nil, pkg.NotFoundError("Subscriber node not found")
	}

	subscription := &pkg.Subscription{
		ID:           uuid.New().String(),
		SubscriberID: subscriberID,
		Topic:        req.Topic,
		Endpoint:     req.Endpoint,
		Filters:      req.Filters,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := em.db.CreateSubscription(subscription); err != nil {
		em.logger.WithError(err).Error("Failed to create subscription")
		return nil, pkg.DatabaseError(err)
	}

	subscriber := &Subscriber{
		ID:           subscription.ID,
		NodeID:       subscriberID,
		Topic:        req.Topic,
		Endpoint:     req.Endpoint,
		Filters:      req.Filters,
		HTTPCallback: true,
		CreatedAt:    time.Now(),
		LastSeen:     time.Now(),
	}

	em.mutex.Lock()
	em.subscribers[req.Topic] = append(em.subscribers[req.Topic], subscriber)
	em.mutex.Unlock()

	em.logger.WithFields(logrus.Fields{
		"subscription_id": subscription.ID,
		"subscriber_id":   subscriberID,
		"topic":           req.Topic,
		"endpoint":        req.Endpoint,
	}).Info("Subscription created")

	return subscription, nil
}

// Unsubscribe removes a subscription
func (em *EventManager) Unsubscribe(subscriptionID string) error {
	subscription, err := em.db.GetSubscription(subscriptionID)
	if err != nil {
		em.logger.WithError(err).Error("Failed to get subscription")
		return pkg.DatabaseError(err)
	}

	if subscription == nil {
		return pkg.NotFoundError("Subscription not found")
	}

	if err := em.db.DeleteSubscription(subscriptionID); err != nil {
		em.logger.WithError(err).Error("Failed to delete subscription")
		return pkg.DatabaseError(err)
	}

	em.mutex.Lock()
	subscribers := em.subscribers[subscription.Topic]
	for i, sub := range subscribers {
		if sub.ID == subscriptionID {
			em.subscribers[subscription.Topic] = append(subscribers[:i], subscribers[i+1:]...)
			break
		}
	}
	em.mutex.Unlock()

	em.logger.WithField("subscription_id", subscriptionID).Info("Subscription removed")

	return nil
}

// ListSubscriptions returns all subscriptions
func (em *EventManager) ListSubscriptions() ([]*pkg.Subscription, error) {
	subscriptions, err := em.db.ListSubscriptions()
	if err != nil {
		em.logger.WithError(err).Error("Failed to list subscriptions")
		return nil, pkg.DatabaseError(err)
	}

	return subscriptions, nil
}

// ListEvents returns events with optional limit
func (em *EventManager) ListEvents(limit int) ([]*pkg.Event, error) {
	if limit <= 0 {
		limit = 100
	}

	events, err := em.db.ListEvents(limit)
	if err != nil {
		em.logger.WithError(err).Error("Failed to list events")
		return nil, pkg.DatabaseError(err)
	}

	return events, nil
}

// Close shuts down the event manager
func (em *EventManager) Close() error {
	em.cancel()

	em.mutex.Lock()
	defer em.mutex.Unlock()

	// Set closed flag first to prevent new events
	em.closed = true

	close(em.eventChannel)
	return nil
}
