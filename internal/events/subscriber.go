package events

import (
	"time"
)

type Subscriber struct {
	ID           string
	NodeID       string
	Topic        string
	Endpoint     string
	Filters      map[string]string
	HTTPCallback bool
	CreatedAt    time.Time
	LastSeen     time.Time
}

// removeSubscriber removes a subscriber from the in-memory store
func (em *EventManager) removeSubscriber(subscriber *Subscriber) {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	subscribers := em.subscribers[subscriber.Topic]
	for i, sub := range subscribers {
		if sub.ID == subscriber.ID {
			em.subscribers[subscriber.Topic] = append(subscribers[:i], subscribers[i+1:]...)
			break
		}
	}

	em.logger.WithField("subscriber_id", subscriber.ID).Info("Subscriber removed")
}

// cleanupInactiveSubscribers runs periodic cleanup of inactive subscribers
func (em *EventManager) cleanupInactiveSubscribers() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-em.ctx.Done():
			return
		case <-ticker.C:
			em.performCleanup()
		}
	}
}

// performCleanup removes inactive subscribers and old events
func (em *EventManager) performCleanup() {
	cutoff := time.Now().Add(-10 * time.Minute)

	em.mutex.Lock()
	defer em.mutex.Unlock()

	for topic, subscribers := range em.subscribers {
		activeSubscribers := make([]*Subscriber, 0, len(subscribers))

		for _, subscriber := range subscribers {
			if subscriber.LastSeen.After(cutoff) {
				activeSubscribers = append(activeSubscribers, subscriber)
			} else {
				em.logger.WithField("subscriber_id", subscriber.ID).Info("Cleaned up inactive subscriber")
			}
		}

		em.subscribers[topic] = activeSubscribers
	}

	if err := em.db.DeleteOldEvents(time.Now().Add(-24 * time.Hour)); err != nil {
		em.logger.WithError(err).Error("Failed to cleanup old events")
	}
}
