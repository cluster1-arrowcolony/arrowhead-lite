package events

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// eventProcessor processes events from the event channel
func (em *EventManager) eventProcessor() {
	for {
		select {
		case <-em.ctx.Done():
			return
		case event := <-em.eventChannel:
			em.distributeEvent(event)
		}
	}
}

// distributeEvent distributes an event to all matching subscribers
func (em *EventManager) distributeEvent(event *pkg.Event) {
	if event == nil {
		return
	}

	em.mutex.RLock()
	subscribers := em.subscribers[event.Topic]
	em.mutex.RUnlock()

	if len(subscribers) == 0 {
		return
	}

	eventData, err := json.Marshal(event)
	if err != nil {
		em.logger.WithError(err).Error("Failed to marshal event for distribution")
		return
	}

	var wg sync.WaitGroup
	for _, subscriber := range subscribers {
		if em.matchesFilters(event, subscriber.Filters) {
			wg.Add(1)
			go func(sub *Subscriber) {
				defer wg.Done()
				em.deliverEvent(sub, eventData)
			}(subscriber)
		}
	}

	wg.Wait()
}

// matchesFilters checks if an event matches subscriber filters
func (em *EventManager) matchesFilters(event *pkg.Event, filters map[string]string) bool {
	if filters == nil {
		return true
	}

	for key, value := range filters {
		switch key {
		case "type":
			if event.Type != value {
				return false
			}
		case "publisher_id":
			if event.PublisherID != value {
				return false
			}
		default:
			if event.Metadata != nil {
				if metaValue, exists := event.Metadata[key]; !exists || metaValue != value {
					return false
				}
			} else {
				return false
			}
		}
	}

	return true
}

// deliverEvent delivers an event to a specific subscriber
func (em *EventManager) deliverEvent(subscriber *Subscriber, eventData []byte) {
	subscriber.LastSeen = time.Now()

	if subscriber.HTTPCallback {
		client := &http.Client{Timeout: 10 * time.Second}
		req, err := http.NewRequest("POST", subscriber.Endpoint, bytes.NewReader(eventData))
		if err != nil {
			em.logger.WithError(err).WithField("subscriber_id", subscriber.ID).Error("Failed to create HTTP request")
			return
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			em.logger.WithError(err).WithField("subscriber_id", subscriber.ID).Error("Failed to deliver event via HTTP")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			em.logger.WithFields(logrus.Fields{
				"subscriber_id": subscriber.ID,
				"status_code":   resp.StatusCode,
			}).Warn("HTTP callback returned error status")
		}
	}
}
