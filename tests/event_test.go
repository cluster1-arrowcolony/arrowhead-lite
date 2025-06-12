package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupEventTest(t *testing.T) (*internal.EventManager, internal.Database) {
	db := setupTestStorage(t)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	eventManager := internal.NewEventManager(db, logger)

	t.Cleanup(func() {
		eventManager.Close()
	})

	return eventManager, db
}

func createTestNode(t *testing.T, db internal.Database, name string, port int) *pkg.Node {
	node := &pkg.Node{
		ID:        name + "-id",
		Name:      name,
		Address:   "localhost",
		Port:      port,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	err := db.CreateNode(node)
	require.NoError(t, err)

	return node
}

func TestEventManager_PublishEvent(t *testing.T) {
	eventManager, db := setupEventTest(t)

	// Create a publisher node
	publisher := createTestNode(t, db, "publisher", 8080)

	// Create and publish an event
	eventReq := &pkg.EventPublishRequest{
		Type:  "sensor-reading",
		Topic: "temperature",
		Payload: map[string]interface{}{
			"temperature": 23.5,
			"unit":        "celsius",
		},
		Metadata: map[string]string{
			"location": "room1",
		},
	}

	event, err := eventManager.PublishEvent(eventReq, publisher.ID)
	require.NoError(t, err)
	require.NotNil(t, event)

	assert.Equal(t, "sensor-reading", event.Type)
	assert.Equal(t, "temperature", event.Topic)
	assert.Equal(t, publisher.ID, event.PublisherID)
	assert.NotEmpty(t, event.ID)
	assert.Equal(t, "room1", event.Metadata["location"])

	// Verify payload can be unmarshaled
	var payload map[string]interface{}
	err = json.Unmarshal(event.Payload, &payload)
	require.NoError(t, err)
	assert.Equal(t, 23.5, payload["temperature"])
	assert.Equal(t, "celsius", payload["unit"])
}

func TestEventManager_PublishEvent_InvalidPayload(t *testing.T) {
	eventManager, db := setupEventTest(t)

	publisher := createTestNode(t, db, "publisher", 8080)

	// Create event with invalid payload (circular reference)
	circularRef := make(map[string]interface{})
	circularRef["self"] = circularRef

	eventReq := &pkg.EventPublishRequest{
		Type:    "invalid-event",
		Topic:   "test",
		Payload: circularRef,
	}

	event, err := eventManager.PublishEvent(eventReq, publisher.ID)
	assert.Error(t, err)
	assert.Nil(t, event)
	assert.Contains(t, err.Error(), "Invalid event payload")
}

func TestEventManager_Subscribe(t *testing.T) {
	eventManager, db := setupEventTest(t)

	// Create a subscriber node
	subscriber := createTestNode(t, db, "subscriber", 8081)

	// Create subscription
	subReq := &pkg.SubscriptionRequest{
		Topic:    "temperature",
		Endpoint: "http://localhost:8081/events",
		Filters: map[string]string{
			"type": "sensor-reading",
		},
	}

	subscription, err := eventManager.Subscribe(subReq, subscriber.ID)
	require.NoError(t, err)
	require.NotNil(t, subscription)

	assert.Equal(t, subscriber.ID, subscription.SubscriberID)
	assert.Equal(t, "temperature", subscription.Topic)
	assert.Equal(t, "http://localhost:8081/events", subscription.Endpoint)
	assert.Equal(t, "sensor-reading", subscription.Filters["type"])
	assert.NotEmpty(t, subscription.ID)
}

func TestEventManager_Subscribe_NodeNotFound(t *testing.T) {
	eventManager, _ := setupEventTest(t)

	subReq := &pkg.SubscriptionRequest{
		Topic:    "temperature",
		Endpoint: "http://localhost:8081/events",
	}

	subscription, err := eventManager.Subscribe(subReq, "non-existent-node")
	assert.Error(t, err)
	assert.Nil(t, subscription)
	assert.Contains(t, err.Error(), "Subscriber node not found")
}

func TestEventManager_ListEvents(t *testing.T) {
	eventManager, db := setupEventTest(t)

	publisher := createTestNode(t, db, "publisher", 8080)

	// Publish multiple events
	for i := 1; i <= 5; i++ {
		eventReq := &pkg.EventPublishRequest{
			Type:  "test-event",
			Topic: "test-topic",
			Payload: map[string]interface{}{
				"counter": i,
			},
		}

		_, err := eventManager.PublishEvent(eventReq, publisher.ID)
		require.NoError(t, err)
	}

	// List events
	events, err := eventManager.ListEvents(10)
	require.NoError(t, err)
	assert.Len(t, events, 5)

	// Verify events are returned (order might vary)
	eventTypes := make(map[string]bool)
	for _, event := range events {
		eventTypes[event.Type] = true
	}
	assert.True(t, eventTypes["test-event"])
}

func TestEventManager_ListEvents_WithLimit(t *testing.T) {
	eventManager, db := setupEventTest(t)

	publisher := createTestNode(t, db, "publisher", 8080)

	// Publish more events than the limit
	for i := 1; i <= 10; i++ {
		eventReq := &pkg.EventPublishRequest{
			Type:  "test-event",
			Topic: "test-topic",
			Payload: map[string]interface{}{
				"counter": i,
			},
		}

		_, err := eventManager.PublishEvent(eventReq, publisher.ID)
		require.NoError(t, err)
	}

	// List events with limit
	events, err := eventManager.ListEvents(3)
	require.NoError(t, err)
	assert.Len(t, events, 3)
}

func TestEventManager_ListSubscriptions(t *testing.T) {
	eventManager, db := setupEventTest(t)

	subscriber1 := createTestNode(t, db, "subscriber1", 8081)
	subscriber2 := createTestNode(t, db, "subscriber2", 8082)

	// Create multiple subscriptions
	subReq1 := &pkg.SubscriptionRequest{
		Topic:    "temperature",
		Endpoint: "http://localhost:8081/events",
	}

	subReq2 := &pkg.SubscriptionRequest{
		Topic:    "humidity",
		Endpoint: "http://localhost:8082/events",
	}

	_, err := eventManager.Subscribe(subReq1, subscriber1.ID)
	require.NoError(t, err)

	_, err = eventManager.Subscribe(subReq2, subscriber2.ID)
	require.NoError(t, err)

	// List subscriptions
	subscriptions, err := eventManager.ListSubscriptions()
	require.NoError(t, err)
	assert.Len(t, subscriptions, 2)

	// Verify subscription details
	topics := make(map[string]bool)
	for _, sub := range subscriptions {
		topics[sub.Topic] = true
	}
	assert.True(t, topics["temperature"])
	assert.True(t, topics["humidity"])
}

func TestEventManager_Unsubscribe(t *testing.T) {
	eventManager, db := setupEventTest(t)

	subscriber := createTestNode(t, db, "subscriber", 8081)

	// Create subscription
	subReq := &pkg.SubscriptionRequest{
		Topic:    "temperature",
		Endpoint: "http://localhost:8081/events",
	}

	subscription, err := eventManager.Subscribe(subReq, subscriber.ID)
	require.NoError(t, err)

	// Verify subscription exists
	subscriptions, err := eventManager.ListSubscriptions()
	require.NoError(t, err)
	assert.Len(t, subscriptions, 1)

	// Unsubscribe
	err = eventManager.Unsubscribe(subscription.ID)
	require.NoError(t, err)

	// Verify subscription is removed
	subscriptions, err = eventManager.ListSubscriptions()
	require.NoError(t, err)
	assert.Len(t, subscriptions, 0)
}

func TestEventManager_Unsubscribe_NotFound(t *testing.T) {
	eventManager, _ := setupEventTest(t)

	err := eventManager.Unsubscribe("non-existent-subscription")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Subscription not found")
}

func TestEventManager_EventDistribution_HTTPCallback(t *testing.T) {
	eventManager, db := setupEventTest(t)

	// Create a mock HTTP server to receive events
	received := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		select {
		case received <- true:
		default:
		}
	}))
	defer server.Close()

	// Create nodes
	publisher := createTestNode(t, db, "publisher", 8080)
	subscriber := createTestNode(t, db, "subscriber", 8081)

	// Create subscription
	subReq := &pkg.SubscriptionRequest{
		Topic:    "temperature",
		Endpoint: server.URL,
	}

	_, err := eventManager.Subscribe(subReq, subscriber.ID)
	require.NoError(t, err)

	// Publish event
	eventReq := &pkg.EventPublishRequest{
		Type:  "sensor-reading",
		Topic: "temperature",
		Payload: map[string]interface{}{
			"temperature": 23.5,
		},
	}

	_, err = eventManager.PublishEvent(eventReq, publisher.ID)
	require.NoError(t, err)

	// Wait for event delivery
	select {
	case <-received:
		// Event was received successfully
	case <-time.After(2 * time.Second):
		t.Fatal("Event was not delivered within timeout")
	}
}

func TestEventManager_EventFiltering(t *testing.T) {
	eventManager, db := setupEventTest(t)

	// Create mock HTTP servers
	receivedTemp := make(chan bool, 1)
	tempServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case receivedTemp <- true:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer tempServer.Close()

	receivedHumidity := make(chan bool, 1)
	humidityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case receivedHumidity <- true:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer humidityServer.Close()

	// Create nodes
	publisher := createTestNode(t, db, "publisher", 8080)
	tempSubscriber := createTestNode(t, db, "temp-subscriber", 8081)
	humiditySubscriber := createTestNode(t, db, "humidity-subscriber", 8082)

	// Create subscriptions with filters
	tempSubReq := &pkg.SubscriptionRequest{
		Topic:    "sensors",
		Endpoint: tempServer.URL,
		Filters: map[string]string{
			"type": "temperature-reading",
		},
	}

	humiditySubReq := &pkg.SubscriptionRequest{
		Topic:    "sensors",
		Endpoint: humidityServer.URL,
		Filters: map[string]string{
			"type": "humidity-reading",
		},
	}

	_, err := eventManager.Subscribe(tempSubReq, tempSubscriber.ID)
	require.NoError(t, err)

	_, err = eventManager.Subscribe(humiditySubReq, humiditySubscriber.ID)
	require.NoError(t, err)

	// Publish temperature event
	tempEventReq := &pkg.EventPublishRequest{
		Type:  "temperature-reading",
		Topic: "sensors",
		Payload: map[string]interface{}{
			"value": 23.5,
		},
	}

	_, err = eventManager.PublishEvent(tempEventReq, publisher.ID)
	require.NoError(t, err)

	// Only temperature subscriber should receive the event
	select {
	case <-receivedTemp:
		// Temperature event received successfully
	case <-time.After(2 * time.Second):
		t.Fatal("Temperature event was not delivered within timeout")
	}

	// Humidity subscriber should not receive the event
	select {
	case <-receivedHumidity:
		t.Fatal("Humidity subscriber should not have received temperature event")
	case <-time.After(100 * time.Millisecond):
		// Expected - no event received
	}
}

func TestEventManager_MetadataFiltering(t *testing.T) {
	eventManager, db := setupEventTest(t)

	// Create mock HTTP server
	received := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case received <- true:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create nodes
	publisher := createTestNode(t, db, "publisher", 8080)
	subscriber := createTestNode(t, db, "subscriber", 8081)

	// Create subscription with metadata filter
	subReq := &pkg.SubscriptionRequest{
		Topic:    "sensors",
		Endpoint: server.URL,
		Filters: map[string]string{
			"location": "room1",
		},
	}

	_, err := eventManager.Subscribe(subReq, subscriber.ID)
	require.NoError(t, err)

	// Publish event with matching metadata
	eventReq := &pkg.EventPublishRequest{
		Type:  "sensor-reading",
		Topic: "sensors",
		Payload: map[string]interface{}{
			"value": 23.5,
		},
		Metadata: map[string]string{
			"location": "room1",
			"sensor":   "temp-01",
		},
	}

	_, err = eventManager.PublishEvent(eventReq, publisher.ID)
	require.NoError(t, err)

	// Event should be received
	select {
	case <-received:
		// Event received successfully
	case <-time.After(2 * time.Second):
		t.Fatal("Event was not delivered within timeout")
	}

	// Clear the channel
	select {
	case <-received:
	default:
	}

	// Publish event with non-matching metadata
	eventReq2 := &pkg.EventPublishRequest{
		Type:  "sensor-reading",
		Topic: "sensors",
		Payload: map[string]interface{}{
			"value": 25.0,
		},
		Metadata: map[string]string{
			"location": "room2", // Different location
			"sensor":   "temp-02",
		},
	}

	_, err = eventManager.PublishEvent(eventReq2, publisher.ID)
	require.NoError(t, err)

	// Event should not be received
	select {
	case <-received:
		t.Fatal("Event with non-matching metadata should not have been delivered")
	case <-time.After(100 * time.Millisecond):
		// Expected - no event received
	}
}

func TestEventManager_Close(t *testing.T) {
	_, db := setupEventTest(t)

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create event manager without automatic cleanup
	eventManager := internal.NewEventManager(db, logger)

	// Create a subscription
	subscriber := createTestNode(t, db, "subscriber", 8081)

	subReq := &pkg.SubscriptionRequest{
		Topic:    "test",
		Endpoint: "http://localhost:8081/events",
	}

	_, err := eventManager.Subscribe(subReq, subscriber.ID)
	require.NoError(t, err)

	// Close event manager
	err = eventManager.Close()
	assert.NoError(t, err)

	// Publishing events after close should not panic (but may not work)
	eventReq := &pkg.EventPublishRequest{
		Type:  "test-event",
		Topic: "test",
		Payload: map[string]interface{}{
			"test": true,
		},
	}

	// This should not panic even though the event manager is closed
	_, err = eventManager.PublishEvent(eventReq, subscriber.ID)
	// Error is expected since the event manager is closed, but it shouldn't panic
}

func TestEventManager_PublisherIdFiltering(t *testing.T) {
	eventManager, db := setupEventTest(t)

	// Create mock HTTP server
	received := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case received <- true:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create nodes
	publisher1 := createTestNode(t, db, "publisher1", 8080)
	publisher2 := createTestNode(t, db, "publisher2", 8081)
	subscriber := createTestNode(t, db, "subscriber", 8082)

	// Create subscription with publisher filter
	subReq := &pkg.SubscriptionRequest{
		Topic:    "sensors",
		Endpoint: server.URL,
		Filters: map[string]string{
			"publisher_id": publisher1.ID,
		},
	}

	_, err := eventManager.Subscribe(subReq, subscriber.ID)
	require.NoError(t, err)

	// Publish event from publisher1 (should match)
	eventReq1 := &pkg.EventPublishRequest{
		Type:  "sensor-reading",
		Topic: "sensors",
		Payload: map[string]interface{}{
			"value": 23.5,
		},
	}

	_, err = eventManager.PublishEvent(eventReq1, publisher1.ID)
	require.NoError(t, err)

	// Event should be received
	select {
	case <-received:
		// Event received successfully
	case <-time.After(2 * time.Second):
		t.Fatal("Event from publisher1 was not delivered within timeout")
	}

	// Clear the channel
	select {
	case <-received:
	default:
	}

	// Publish event from publisher2 (should not match)
	eventReq2 := &pkg.EventPublishRequest{
		Type:  "sensor-reading",
		Topic: "sensors",
		Payload: map[string]interface{}{
			"value": 25.0,
		},
	}

	_, err = eventManager.PublishEvent(eventReq2, publisher2.ID)
	require.NoError(t, err)

	// Event should not be received
	select {
	case <-received:
		t.Fatal("Event from publisher2 should not have been delivered")
	case <-time.After(100 * time.Millisecond):
		// Expected - no event received
	}
}
