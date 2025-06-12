package tests

import (
	"os"
	"testing"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestStorage(t *testing.T) internal.Database {
	// Use SQLite for tests (simpler, no external dependencies)
	dbPath := "/tmp/test_storage_" + time.Now().Format("20060102150405") + ".db"

	db, err := internal.NewStorage("sqlite", dbPath)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
		os.Remove(dbPath)
	})

	return db
}

func TestNodeCRUD(t *testing.T) {
	db := setupTestStorage(t)

	node := &pkg.Node{
		ID:        "test-node-1",
		Name:      "Test Node",
		Address:   "192.168.1.100",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
		Metadata:  map[string]string{"type": "sensor"},
	}

	err := db.CreateNode(node)
	require.NoError(t, err, "Node should be created without error")

	retrieved, err := db.GetNode("test-node-1")
	require.NoError(t, err, "Node should be retrievable")
	require.NotNil(t, retrieved)

	assert.Equal(t, node.ID, retrieved.ID)
	assert.Equal(t, node.Name, retrieved.Name)
	assert.Equal(t, node.Address, retrieved.Address)
	assert.Equal(t, node.Port, retrieved.Port)
	assert.Equal(t, node.Status, retrieved.Status)
	assert.Equal(t, "sensor", retrieved.Metadata["type"])

	retrieved.Address = "192.168.1.101"
	retrieved.UpdatedAt = time.Now()
	err = db.UpdateNode(retrieved)
	require.NoError(t, err, "Node update should succeed")

	updated, err := db.GetNode("test-node-1")
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.101", updated.Address, "Updated address should match")

	nodes, err := db.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 1, "There should be one node in the list")

	err = db.DeleteNode("test-node-1")
	require.NoError(t, err, "Node deletion should succeed")

	deleted, err := db.GetNode("test-node-1")
	require.NoError(t, err)
	assert.Nil(t, deleted, "Deleted node should not be retrievable")
}

func TestServiceCRUD(t *testing.T) {
	db := setupTestStorage(t)

	node := &pkg.Node{
		ID:        "test-node-1",
		Name:      "Test Node",
		Address:   "localhost",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	err := db.CreateNode(node)
	require.NoError(t, err)

	service := &pkg.Service{
		ID:         "test-service-1",
		Name:       "temperature-sensor",
		NodeID:     "test-node-1",
		Definition: "temperature-reading",
		URI:        "/api/temperature",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastSeen:   time.Now(),
		Metadata:   map[string]string{"unit": "celsius"},
	}

	err = db.CreateService(service)
	require.NoError(t, err, "Service should be created without error")

	retrieved, err := db.GetService("test-service-1")
	require.NoError(t, err, "Service should be retrievable")
	require.NotNil(t, retrieved)

	assert.Equal(t, service.ID, retrieved.ID)
	assert.Equal(t, service.Name, retrieved.Name)
	assert.Equal(t, service.NodeID, retrieved.NodeID)
	assert.Equal(t, service.Definition, retrieved.Definition)
	assert.Equal(t, service.URI, retrieved.URI)
	assert.Equal(t, service.Method, retrieved.Method)
	assert.Equal(t, "celsius", retrieved.Metadata["unit"])

	services, err := db.GetServicesByNode("test-node-1")
	require.NoError(t, err)
	assert.Len(t, services, 1)

	servicesByName, err := db.GetServicesByName("temperature-sensor")
	require.NoError(t, err)
	assert.Len(t, servicesByName, 1)

	allServices, err := db.ListServices()
	require.NoError(t, err)
	assert.Len(t, allServices, 1)

	err = db.DeleteService("test-service-1")
	require.NoError(t, err)

	deleted, err := db.GetService("test-service-1")
	require.NoError(t, err)
	assert.Nil(t, deleted)
}

func TestAuthRuleCRUD(t *testing.T) {
	db := setupTestStorage(t)

	consumer := &pkg.Node{
		ID:        "consumer-1",
		Name:      "Consumer Node",
		Address:   "localhost",
		Port:      8081,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	provider := &pkg.Node{
		ID:        "provider-1",
		Name:      "Provider Node",
		Address:   "localhost",
		Port:      8082,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	service := &pkg.Service{
		ID:         "service-1",
		Name:       "test-service",
		NodeID:     "provider-1",
		Definition: "test-definition",
		URI:        "/test",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(provider))
	require.NoError(t, db.CreateService(service))

	authRule := &pkg.AuthRule{
		ID:         "auth-rule-1",
		ConsumerID: "consumer-1",
		ProviderID: "provider-1",
		ServiceID:  "service-1",
		CreatedAt:  time.Now(),
	}

	err := db.CreateAuthRule(authRule)
	require.NoError(t, err, "AuthRule should be created without error")

	retrieved, err := db.GetAuthRule("auth-rule-1")
	require.NoError(t, err)
	require.NotNil(t, retrieved, "AuthRule should be retrievable")

	assert.Equal(t, authRule.ID, retrieved.ID)
	assert.Equal(t, authRule.ConsumerID, retrieved.ConsumerID)
	assert.Equal(t, authRule.ProviderID, retrieved.ProviderID)
	assert.Equal(t, authRule.ServiceID, retrieved.ServiceID)

	rules, err := db.GetAuthRules("consumer-1", "provider-1", "service-1")
	require.NoError(t, err)
	assert.Len(t, rules, 1, "Should retrieve one auth rule")

	allRules, err := db.ListAuthRules()
	require.NoError(t, err)
	assert.Len(t, allRules, 1, "Should list one auth rule")

	err = db.DeleteAuthRule("auth-rule-1")
	require.NoError(t, err, "AuthRule deletion should succeed")

	deleted, err := db.GetAuthRule("auth-rule-1")
	require.NoError(t, err)
	assert.Nil(t, deleted, "Deleted AuthRule should not be retrievable")
}

func TestEventCRUD(t *testing.T) {
	db := setupTestStorage(t)

	node := &pkg.Node{
		ID:        "publisher-1",
		Name:      "Publisher Node",
		Address:   "localhost",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	require.NoError(t, db.CreateNode(node))

	event := &pkg.Event{
		ID:          "event-1",
		Type:        "sensor-reading",
		Topic:       "temperature",
		PublisherID: "publisher-1",
		Payload:     []byte(`{"temperature": 23.5, "unit": "celsius"}`),
		Metadata:    map[string]string{"location": "room1"},
		CreatedAt:   time.Now(),
	}

	err := db.CreateEvent(event)
	require.NoError(t, err, "Event should be created without error")

	retrieved, err := db.GetEvent("event-1")
	require.NoError(t, err)
	require.NotNil(t, retrieved, "Event should be retrievable")

	assert.Equal(t, event.ID, retrieved.ID)
	assert.Equal(t, event.Type, retrieved.Type)
	assert.Equal(t, event.Topic, retrieved.Topic)
	assert.Equal(t, event.PublisherID, retrieved.PublisherID)
	assert.Equal(t, event.Payload, retrieved.Payload)
	assert.Equal(t, "room1", retrieved.Metadata["location"])

	events, err := db.ListEvents(10)
	require.NoError(t, err)
	assert.Len(t, events, 1, "Should list one event")

	pastTime := time.Now().Add(-1 * time.Hour)
	err = db.DeleteOldEvents(pastTime)
	require.NoError(t, err, "DeleteOldEvents should succeed")

	events, err = db.ListEvents(10)
	require.NoError(t, err)
	assert.Len(t, events, 1, "Should still have one event after deleting old events")

	futureTime := time.Now().Add(1 * time.Hour)
	err = db.DeleteOldEvents(futureTime)
	require.NoError(t, err, "DeleteOldEvents should succeed")

	events, err = db.ListEvents(10)
	require.NoError(t, err)
	assert.Len(t, events, 0, "Should have no events after deleting future events")
}

func TestSubscriptionCRUD(t *testing.T) {
	db := setupTestStorage(t)

	node := &pkg.Node{
		ID:        "subscriber-1",
		Name:      "Subscriber Node",
		Address:   "localhost",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	require.NoError(t, db.CreateNode(node))

	subscription := &pkg.Subscription{
		ID:           "sub-1",
		SubscriberID: "subscriber-1",
		Topic:        "temperature",
		Endpoint:     "http://localhost:8080/events",
		Filters:      map[string]string{"type": "sensor-reading"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err := db.CreateSubscription(subscription)
	require.NoError(t, err, "Subscription should be created without error")

	retrieved, err := db.GetSubscription("sub-1")
	require.NoError(t, err)
	require.NotNil(t, retrieved, "Subscription should be retrievable")

	assert.Equal(t, subscription.ID, retrieved.ID)
	assert.Equal(t, subscription.SubscriberID, retrieved.SubscriberID)
	assert.Equal(t, subscription.Topic, retrieved.Topic)
	assert.Equal(t, subscription.Endpoint, retrieved.Endpoint)
	assert.Equal(t, "sensor-reading", retrieved.Filters["type"])

	subscriptions, err := db.GetSubscriptionsByTopic("temperature")
	require.NoError(t, err)
	assert.Len(t, subscriptions, 1, "Should retrieve one subscription for topic 'temperature'")

	retrieved.Endpoint = "http://localhost:8081/events"
	retrieved.UpdatedAt = time.Now()
	err = db.UpdateSubscription(retrieved)
	require.NoError(t, err, "Subscription update should succeed")

	updated, err := db.GetSubscription("sub-1")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8081/events", updated.Endpoint, "Updated endpoint should match")

	allSubscriptions, err := db.ListSubscriptions()
	require.NoError(t, err)
	assert.Len(t, allSubscriptions, 1)

	err = db.DeleteSubscription("sub-1")
	require.NoError(t, err)

	deleted, err := db.GetSubscription("sub-1")
	require.NoError(t, err)
	assert.Nil(t, deleted)
}

func TestMetrics(t *testing.T) {
	db := setupTestStorage(t)

	node1 := &pkg.Node{
		ID:        "node-1",
		Name:      "Node 1",
		Address:   "localhost",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	node2 := &pkg.Node{
		ID:        "node-2",
		Name:      "Node 2",
		Address:   "localhost",
		Port:      8081,
		Status:    pkg.NodeStatusOffline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	require.NoError(t, db.CreateNode(node1))
	require.NoError(t, db.CreateNode(node2))

	service1 := &pkg.Service{
		ID:         "service-1",
		Name:       "Active Service",
		NodeID:     "node-1",
		Definition: "test-def-1",
		URI:        "/test1",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	service2 := &pkg.Service{
		ID:         "service-2",
		Name:       "Inactive Service",
		NodeID:     "node-2",
		Definition: "test-def-2",
		URI:        "/test2",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusInactive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateService(service1))
	require.NoError(t, db.CreateService(service2))

	event := &pkg.Event{
		ID:          "event-1",
		Type:        "test-event",
		Topic:       "test",
		PublisherID: "node-1",
		Payload:     []byte(`{"test": true}`),
		CreatedAt:   time.Now(),
	}

	require.NoError(t, db.CreateEvent(event))

	subscription := &pkg.Subscription{
		ID:           "sub-1",
		SubscriberID: "node-1",
		Topic:        "test",
		Endpoint:     "http://localhost:8080/events",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	require.NoError(t, db.CreateSubscription(subscription))

	metrics, err := db.GetMetrics()
	require.NoError(t, err)

	assert.Equal(t, int64(2), metrics.TotalNodes)
	assert.Equal(t, int64(1), metrics.ActiveNodes)
	assert.Equal(t, int64(2), metrics.TotalServices)
	assert.Equal(t, int64(1), metrics.ActiveServices)
	assert.Equal(t, int64(1), metrics.TotalEvents)
	assert.Equal(t, int64(1), metrics.TotalSubscriptions)
}
