package tests

import (
	"fmt"
	"testing"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupOrchestrationTest(t *testing.T) (*internal.Orchestrator, internal.Database) {
	db := setupTestStorage(t)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	orchestrator := internal.NewOrchestrator(db, logger)
	return orchestrator, db
}

func TestOrchestration_BasicServiceDiscovery(t *testing.T) {
	orchestrator, db := setupOrchestrationTest(t)

	// Setup test data
	consumer := &pkg.Node{
		ID:       "consumer-1",
		Name:     "Consumer Node",
		Address:  "192.168.1.100",
		Port:     8080,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	provider := &pkg.Node{
		ID:       "provider-1",
		Name:     "Provider Node",
		Address:  "192.168.1.101",
		Port:     8081,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	service := &pkg.Service{
		ID:         "service-1",
		Name:       "temperature-sensor",
		NodeID:     "provider-1",
		Definition: "temperature-reading",
		URI:        "/api/temperature",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(provider))
	require.NoError(t, db.CreateService(service))

	// Test orchestration request
	req := &pkg.OrchestrationRequest{
		RequesterID: "consumer-1",
		ServiceName: "temperature-sensor",
	}

	response, err := orchestrator.Orchestrate(req)
	require.NoError(t, err)
	require.NotNil(t, response)

	assert.Len(t, response.Services, 1)
	assert.Equal(t, service.ID, response.Services[0].Service.ID)
	assert.Equal(t, provider.ID, response.Services[0].Node.ID)
	assert.Contains(t, response.Services[0].Endpoint, "192.168.1.101:8081")
	assert.Contains(t, response.Services[0].Endpoint, "/api/temperature")
}

func TestOrchestration_NoServicesFound(t *testing.T) {
	orchestrator, db := setupOrchestrationTest(t)

	consumer := &pkg.Node{
		ID:       "consumer-1",
		Name:     "Consumer Node",
		Address:  "192.168.1.100",
		Port:     8080,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))

	req := &pkg.OrchestrationRequest{
		RequesterID: "consumer-1",
		ServiceName: "non-existent-service",
	}

	response, err := orchestrator.Orchestrate(req)
	require.NoError(t, err)
	require.NotNil(t, response)

	assert.Len(t, response.Services, 0)
}

func TestOrchestration_RequesterNotFound(t *testing.T) {
	orchestrator, _ := setupOrchestrationTest(t)

	req := &pkg.OrchestrationRequest{
		RequesterID: "non-existent-consumer",
		ServiceName: "temperature-sensor",
	}

	response, err := orchestrator.Orchestrate(req)
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "Requester node not found")
}

func TestOrchestration_FilterByVersion(t *testing.T) {
	orchestrator, db := setupOrchestrationTest(t)

	consumer := &pkg.Node{
		ID:       "consumer-1",
		Name:     "Consumer Node",
		Address:  "localhost",
		Port:     8080,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	provider := &pkg.Node{
		ID:       "provider-1",
		Name:     "Provider Node",
		Address:  "localhost",
		Port:     8081,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	service1 := &pkg.Service{
		ID:         "service-1",
		Name:       "temperature-sensor",
		NodeID:     "provider-1",
		Definition: "temperature-reading",
		URI:        "/api/temperature",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	service2 := &pkg.Service{
		ID:         "service-2",
		Name:       "temperature-sensor",
		NodeID:     "provider-1",
		Definition: "temperature-reading",
		URI:        "/api/temperature/v2",
		Method:     "GET",
		Version:    "2.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(provider))
	require.NoError(t, db.CreateService(service1))
	require.NoError(t, db.CreateService(service2))

	// Test filtering by version
	req := &pkg.OrchestrationRequest{
		RequesterID: "consumer-1",
		ServiceName: "temperature-sensor",
		Filters: map[string]interface{}{
			"version": "2.0",
		},
	}

	response, err := orchestrator.Orchestrate(req)
	require.NoError(t, err)
	require.NotNil(t, response)

	assert.Len(t, response.Services, 1)
	assert.Equal(t, service2.ID, response.Services[0].Service.ID)
	assert.Equal(t, "2.0", response.Services[0].Service.Version)
}

func TestOrchestration_FilterByMethod(t *testing.T) {
	orchestrator, db := setupOrchestrationTest(t)

	consumer := &pkg.Node{
		ID:       "consumer-1",
		Name:     "Consumer Node",
		Address:  "localhost",
		Port:     8080,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	provider := &pkg.Node{
		ID:       "provider-1",
		Name:     "Provider Node",
		Address:  "localhost",
		Port:     8081,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	getService := &pkg.Service{
		ID:         "service-1",
		Name:       "sensor-api",
		NodeID:     "provider-1",
		Definition: "sensor-control",
		URI:        "/api/sensor",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	postService := &pkg.Service{
		ID:         "service-2",
		Name:       "sensor-api",
		NodeID:     "provider-1",
		Definition: "sensor-control",
		URI:        "/api/sensor",
		Method:     "POST",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(provider))
	require.NoError(t, db.CreateService(getService))
	require.NoError(t, db.CreateService(postService))

	req := &pkg.OrchestrationRequest{
		RequesterID: "consumer-1",
		ServiceName: "sensor-api",
		Filters: map[string]interface{}{
			"method": "POST",
		},
	}

	response, err := orchestrator.Orchestrate(req)
	require.NoError(t, err)
	require.NotNil(t, response)

	assert.Len(t, response.Services, 1)
	assert.Equal(t, postService.ID, response.Services[0].Service.ID)
	assert.Equal(t, "POST", response.Services[0].Service.Method)
}

func TestOrchestration_ServiceRanking(t *testing.T) {
	orchestrator, db := setupOrchestrationTest(t)

	consumer := &pkg.Node{
		ID:       "consumer-1",
		Name:     "Consumer Node",
		Address:  "localhost",
		Port:     8080,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	// Local provider (same address as consumer)
	localProvider := &pkg.Node{
		ID:       "provider-local",
		Name:     "Local Provider",
		Address:  "localhost", // Same as consumer
		Port:     8081,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	// Remote provider (different address)
	remoteProvider := &pkg.Node{
		ID:       "provider-remote",
		Name:     "Remote Provider",
		Address:  "192.168.1.100", // Different address
		Port:     8082,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	localService := &pkg.Service{
		ID:         "local-service",
		Name:       "temperature-sensor",
		NodeID:     "provider-local",
		Definition: "temperature-reading",
		URI:        "/api/temperature",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	remoteService := &pkg.Service{
		ID:         "remote-service",
		Name:       "temperature-sensor",
		NodeID:     "provider-remote",
		Definition: "temperature-reading",
		URI:        "/api/temperature",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(localProvider))
	require.NoError(t, db.CreateNode(remoteProvider))
	require.NoError(t, db.CreateService(localService))
	require.NoError(t, db.CreateService(remoteService))

	req := &pkg.OrchestrationRequest{
		RequesterID: "consumer-1",
		ServiceName: "temperature-sensor",
	}

	response, err := orchestrator.Orchestrate(req)
	require.NoError(t, err)
	require.NotNil(t, response)

	assert.Len(t, response.Services, 2)

	// Local service should be ranked higher (first in results)
	assert.Equal(t, localService.ID, response.Services[0].Service.ID)
	assert.Equal(t, remoteService.ID, response.Services[1].Service.ID)
}

func TestOrchestration_PreferredProvider(t *testing.T) {
	orchestrator, db := setupOrchestrationTest(t)

	consumer := &pkg.Node{
		ID:       "consumer-1",
		Name:     "Consumer Node",
		Address:  "localhost",
		Port:     8080,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	provider1 := &pkg.Node{
		ID:       "provider-1",
		Name:     "Standard Provider",
		Address:  "localhost",
		Port:     8081,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	provider2 := &pkg.Node{
		ID:       "provider-2",
		Name:     "Premium Provider",
		Address:  "localhost",
		Port:     8082,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	service1 := &pkg.Service{
		ID:         "service-1",
		Name:       "temperature-sensor",
		NodeID:     "provider-1",
		Definition: "temperature-reading",
		URI:        "/api/temperature",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	service2 := &pkg.Service{
		ID:         "service-2",
		Name:       "temperature-sensor",
		NodeID:     "provider-2",
		Definition: "temperature-reading",
		URI:        "/api/temperature",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(provider1))
	require.NoError(t, db.CreateNode(provider2))
	require.NoError(t, db.CreateService(service1))
	require.NoError(t, db.CreateService(service2))

	req := &pkg.OrchestrationRequest{
		RequesterID: "consumer-1",
		ServiceName: "temperature-sensor",
		Preferences: map[string]interface{}{
			"preferred_provider": "Premium Provider",
		},
	}

	response, err := orchestrator.Orchestrate(req)
	require.NoError(t, err)
	require.NotNil(t, response)

	assert.Len(t, response.Services, 2)

	// Premium Provider should be ranked first due to preference
	assert.Equal(t, service2.ID, response.Services[0].Service.ID)
	assert.Equal(t, "Premium Provider", response.Services[0].Node.Name)
}

func TestOrchestration_InactiveServicesFiltered(t *testing.T) {
	orchestrator, db := setupOrchestrationTest(t)

	consumer := &pkg.Node{
		ID:       "consumer-1",
		Name:     "Consumer Node",
		Address:  "localhost",
		Port:     8080,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	provider := &pkg.Node{
		ID:       "provider-1",
		Name:     "Provider Node",
		Address:  "localhost",
		Port:     8081,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	activeService := &pkg.Service{
		ID:         "active-service",
		Name:       "temperature-sensor",
		NodeID:     "provider-1",
		Definition: "temperature-reading",
		URI:        "/api/temperature",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	inactiveService := &pkg.Service{
		ID:         "inactive-service",
		Name:       "temperature-sensor",
		NodeID:     "provider-1",
		Definition: "temperature-reading",
		URI:        "/api/temperature/old",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusInactive, // Inactive status
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(provider))
	require.NoError(t, db.CreateService(activeService))
	require.NoError(t, db.CreateService(inactiveService))

	req := &pkg.OrchestrationRequest{
		RequesterID: "consumer-1",
		ServiceName: "temperature-sensor",
	}

	response, err := orchestrator.Orchestrate(req)
	require.NoError(t, err)
	require.NotNil(t, response)

	// Only active service should be returned
	assert.Len(t, response.Services, 1)
	assert.Equal(t, activeService.ID, response.Services[0].Service.ID)
}

func TestOrchestration_OfflineNodesFiltered(t *testing.T) {
	orchestrator, db := setupOrchestrationTest(t)

	consumer := &pkg.Node{
		ID:       "consumer-1",
		Name:     "Consumer Node",
		Address:  "localhost",
		Port:     8080,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	onlineProvider := &pkg.Node{
		ID:       "provider-online",
		Name:     "Online Provider",
		Address:  "localhost",
		Port:     8081,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	offlineProvider := &pkg.Node{
		ID:       "provider-offline",
		Name:     "Offline Provider",
		Address:  "localhost",
		Port:     8082,
		Status:   pkg.NodeStatusOffline, // Offline status
		LastSeen: time.Now(),
	}

	onlineService := &pkg.Service{
		ID:         "online-service",
		Name:       "temperature-sensor",
		NodeID:     "provider-online",
		Definition: "temperature-reading",
		URI:        "/api/temperature",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	offlineService := &pkg.Service{
		ID:         "offline-service",
		Name:       "temperature-sensor",
		NodeID:     "provider-offline",
		Definition: "temperature-reading",
		URI:        "/api/temperature",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(onlineProvider))
	require.NoError(t, db.CreateNode(offlineProvider))
	require.NoError(t, db.CreateService(onlineService))
	require.NoError(t, db.CreateService(offlineService))

	req := &pkg.OrchestrationRequest{
		RequesterID: "consumer-1",
		ServiceName: "temperature-sensor",
	}

	response, err := orchestrator.Orchestrate(req)
	require.NoError(t, err)
	require.NotNil(t, response)

	// Only service from online node should be returned
	assert.Len(t, response.Services, 1)
	assert.Equal(t, onlineService.ID, response.Services[0].Service.ID)
	assert.Equal(t, onlineProvider.ID, response.Services[0].Node.ID)
}

func TestOrchestration_MaxResultsLimit(t *testing.T) {
	orchestrator, db := setupOrchestrationTest(t)

	consumer := &pkg.Node{
		ID:       "consumer-1",
		Name:     "Consumer Node",
		Address:  "localhost",
		Port:     8080,
		Status:   pkg.NodeStatusOnline,
		LastSeen: time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))

	// Create multiple providers and services
	for i := 1; i <= 15; i++ {
		provider := &pkg.Node{
			ID:       fmt.Sprintf("provider-%d", i),
			Name:     fmt.Sprintf("Provider %d", i),
			Address:  "localhost",
			Port:     8080 + i,
			Status:   pkg.NodeStatusOnline,
			LastSeen: time.Now(),
		}

		service := &pkg.Service{
			ID:         fmt.Sprintf("service-%d", i),
			Name:       "temperature-sensor",
			NodeID:     fmt.Sprintf("provider-%d", i),
			Definition: "temperature-reading",
			URI:        "/api/temperature",
			Method:     "GET",
			Version:    "1.0",
			Status:     pkg.ServiceStatusActive,
			LastSeen:   time.Now(),
		}

		require.NoError(t, db.CreateNode(provider))
		require.NoError(t, db.CreateService(service))
	}

	req := &pkg.OrchestrationRequest{
		RequesterID: "consumer-1",
		ServiceName: "temperature-sensor",
		Preferences: map[string]interface{}{
			"max_results": float64(5), // Limit to 5 results
		},
	}

	response, err := orchestrator.Orchestrate(req)
	require.NoError(t, err)
	require.NotNil(t, response)

	// Should be limited to 5 results
	assert.Len(t, response.Services, 5)
}
