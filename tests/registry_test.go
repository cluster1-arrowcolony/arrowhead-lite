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

func setupRegistryTest(t *testing.T) (*internal.Registry, internal.Database) {
	db := setupTestStorage(t)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	registry := internal.NewRegistry(db, logger)

	return registry, db
}

func TestRegistry_RegisterNode(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Create registration request
	req := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:     "Test Node",
			Address:  "localhost",
			Port:     8080,
			Metadata: map[string]string{"type": "sensor"},
		},
	}

	// Register node
	node, err := registry.RegisterNode(req)
	require.NoError(t, err)
	require.NotNil(t, node)

	// Verify node properties
	assert.Equal(t, "Test Node", node.Name)
	assert.Equal(t, "localhost", node.Address)
	assert.Equal(t, 8080, node.Port)
	assert.Equal(t, pkg.NodeStatusOnline, node.Status)
	assert.NotEmpty(t, node.ID)
	assert.Equal(t, "sensor", node.Metadata["type"])
	assert.False(t, node.CreatedAt.IsZero())
	assert.False(t, node.UpdatedAt.IsZero())
	assert.False(t, node.LastSeen.IsZero())
}

func TestRegistry_RegisterNode_WithID(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Create registration request with predefined ID
	req := &pkg.RegistrationRequest{
		Node: pkg.Node{
			ID:      "custom-node-id",
			Name:    "Test Node",
			Address: "localhost",
			Port:    8080,
		},
	}

	// Register node
	node, err := registry.RegisterNode(req)
	require.NoError(t, err)
	require.NotNil(t, node)

	// Verify the custom ID is preserved
	assert.Equal(t, "custom-node-id", node.ID)
	assert.Equal(t, "Test Node", node.Name)
}

func TestRegistry_RegisterNode_DuplicateName(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Register first node
	req1 := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Test Node",
			Address: "localhost",
			Port:    8080,
		},
	}

	_, err := registry.RegisterNode(req1)
	require.NoError(t, err)

	// Try to register node with same name
	req2 := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Test Node", // Same name
			Address: "localhost",
			Port:    8081,
		},
	}

	node2, err := registry.RegisterNode(req2)
	assert.Error(t, err)
	assert.Nil(t, node2)
	assert.Contains(t, err.Error(), "Node with this name already exists")
}

func TestRegistry_RegisterService(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// First register a node
	nodeReq := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Provider Node",
			Address: "localhost",
			Port:    8080,
		},
	}

	node, err := registry.RegisterNode(nodeReq)
	require.NoError(t, err)

	// Register service
	serviceReq := &pkg.RegistrationRequest{
		Service: pkg.Service{
			Name:       "temperature-sensor",
			NodeID:     node.ID,
			Definition: "temperature-reading",
			URI:        "/api/temperature",
			Method:     "GET",
			Metadata:   map[string]string{"unit": "celsius"},
		},
	}

	service, err := registry.RegisterService(serviceReq)
	require.NoError(t, err)
	require.NotNil(t, service)

	// Verify service properties
	assert.Equal(t, "temperature-sensor", service.Name)
	assert.Equal(t, node.ID, service.NodeID)
	assert.Equal(t, "temperature-reading", service.Definition)
	assert.Equal(t, "/api/temperature", service.URI)
	assert.Equal(t, "GET", service.Method)
	assert.Equal(t, "1.0", service.Version) // Default version
	assert.Equal(t, pkg.ServiceStatusActive, service.Status)
	assert.NotEmpty(t, service.ID)
	assert.Equal(t, "celsius", service.Metadata["unit"])
	assert.False(t, service.CreatedAt.IsZero())
	assert.False(t, service.UpdatedAt.IsZero())
	assert.False(t, service.LastSeen.IsZero())
}

func TestRegistry_RegisterService_WithVersion(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// First register a node
	nodeReq := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Provider Node",
			Address: "localhost",
			Port:    8080,
		},
	}

	node, err := registry.RegisterNode(nodeReq)
	require.NoError(t, err)

	// Register service with custom version
	serviceReq := &pkg.RegistrationRequest{
		Service: pkg.Service{
			Name:       "temperature-sensor",
			NodeID:     node.ID,
			Definition: "temperature-reading",
			URI:        "/api/temperature",
			Method:     "GET",
			Version:    "2.1",
		},
	}

	service, err := registry.RegisterService(serviceReq)
	require.NoError(t, err)
	require.NotNil(t, service)

	// Verify custom version is preserved
	assert.Equal(t, "2.1", service.Version)
}

func TestRegistry_RegisterService_NodeNotFound(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Try to register service with non-existent node
	serviceReq := &pkg.RegistrationRequest{
		Service: pkg.Service{
			Name:       "test-service",
			NodeID:     "non-existent-node",
			Definition: "test-definition",
			URI:        "/test",
			Method:     "GET",
		},
	}

	service, err := registry.RegisterService(serviceReq)
	assert.Error(t, err)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "Node not found")
}

func TestRegistry_RegisterService_NoNodeID(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Try to register service without node ID
	serviceReq := &pkg.RegistrationRequest{
		Service: pkg.Service{
			Name:       "test-service",
			Definition: "test-definition",
			URI:        "/test",
			Method:     "GET",
		},
	}

	service, err := registry.RegisterService(serviceReq)
	assert.Error(t, err)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "Node ID is required")
}

func TestRegistry_GetNode(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Register a node
	req := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Test Node",
			Address: "localhost",
			Port:    8080,
		},
	}

	registered, err := registry.RegisterNode(req)
	require.NoError(t, err)

	// Get the node
	node, err := registry.GetNode(registered.ID)
	require.NoError(t, err)
	require.NotNil(t, node)

	assert.Equal(t, registered.ID, node.ID)
	assert.Equal(t, registered.Name, node.Name)
	assert.Equal(t, registered.Address, node.Address)
	assert.Equal(t, registered.Port, node.Port)
}

func TestRegistry_GetNode_NotFound(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	node, err := registry.GetNode("non-existent-node")
	assert.Error(t, err)
	assert.Nil(t, node)
	assert.Contains(t, err.Error(), "Node not found")
}

func TestRegistry_GetNodeByName(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Register a node
	req := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Test Node",
			Address: "localhost",
			Port:    8080,
		},
	}

	registered, err := registry.RegisterNode(req)
	require.NoError(t, err)

	// Get the node by name
	node, err := registry.GetNodeByName("Test Node")
	require.NoError(t, err)
	require.NotNil(t, node)

	assert.Equal(t, registered.ID, node.ID)
	assert.Equal(t, registered.Name, node.Name)
}

func TestRegistry_GetNodeByName_NotFound(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	node, err := registry.GetNodeByName("Non-existent Node")
	assert.Error(t, err)
	assert.Nil(t, node)
	assert.Contains(t, err.Error(), "Node not found")
}

func TestRegistry_GetService(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Setup node and service
	node, service := setupNodeAndService(t, registry)

	// Get the service
	retrieved, err := registry.GetService(service.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, service.ID, retrieved.ID)
	assert.Equal(t, service.Name, retrieved.Name)
	assert.Equal(t, node.ID, retrieved.NodeID)
}

func TestRegistry_GetService_NotFound(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	service, err := registry.GetService("non-existent-service")
	assert.Error(t, err)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "Service not found")
}

func TestRegistry_ListNodes(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Register multiple nodes
	for i := 1; i <= 3; i++ {
		req := &pkg.RegistrationRequest{
			Node: pkg.Node{
				Name:    fmt.Sprintf("Node %d", i),
				Address: "localhost",
				Port:    8080 + i,
			},
		}

		_, err := registry.RegisterNode(req)
		require.NoError(t, err)
	}

	// List nodes
	nodes, err := registry.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 3)

	// Verify all nodes are present
	names := make(map[string]bool)
	for _, node := range nodes {
		names[node.Name] = true
	}

	for i := 1; i <= 3; i++ {
		assert.True(t, names[fmt.Sprintf("Node %d", i)])
	}
}

func TestRegistry_ListServices(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Setup node
	nodeReq := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Provider Node",
			Address: "localhost",
			Port:    8080,
		},
	}

	node, err := registry.RegisterNode(nodeReq)
	require.NoError(t, err)

	// Register multiple services
	for i := 1; i <= 3; i++ {
		serviceReq := &pkg.RegistrationRequest{
			Service: pkg.Service{
				Name:       fmt.Sprintf("service-%d", i),
				NodeID:     node.ID,
				Definition: fmt.Sprintf("definition-%d", i),
				URI:        fmt.Sprintf("/api/service%d", i),
				Method:     "GET",
			},
		}

		_, err := registry.RegisterService(serviceReq)
		require.NoError(t, err)
	}

	// List services
	services, err := registry.ListServices()
	require.NoError(t, err)
	assert.Len(t, services, 3)

	// Verify all services are present
	names := make(map[string]bool)
	for _, service := range services {
		names[service.Name] = true
	}

	for i := 1; i <= 3; i++ {
		assert.True(t, names[fmt.Sprintf("service-%d", i)])
	}
}

func TestRegistry_ListServicesByNode(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Setup two nodes
	node1, _ := setupNodeAndService(t, registry)

	nodeReq2 := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Node 2",
			Address: "localhost",
			Port:    8081,
		},
	}

	node2, err := registry.RegisterNode(nodeReq2)
	require.NoError(t, err)

	// Register services for node2
	for i := 1; i <= 2; i++ {
		serviceReq := &pkg.RegistrationRequest{
			Service: pkg.Service{
				Name:       fmt.Sprintf("node2-service-%d", i),
				NodeID:     node2.ID,
				Definition: fmt.Sprintf("definition-%d", i),
				URI:        fmt.Sprintf("/api/service%d", i),
				Method:     "GET",
			},
		}

		_, err := registry.RegisterService(serviceReq)
		require.NoError(t, err)
	}

	// List services for node1 (should have 1 service from setupNodeAndService)
	services1, err := registry.ListServicesByNode(node1.ID)
	require.NoError(t, err)
	assert.Len(t, services1, 1)

	// List services for node2 (should have 2 services)
	services2, err := registry.ListServicesByNode(node2.ID)
	require.NoError(t, err)
	assert.Len(t, services2, 2)

	// Verify services belong to correct nodes
	for _, service := range services1 {
		assert.Equal(t, node1.ID, service.NodeID)
	}

	for _, service := range services2 {
		assert.Equal(t, node2.ID, service.NodeID)
	}
}

func TestRegistry_FindServicesByName(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Setup node
	nodeReq := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Provider Node",
			Address: "localhost",
			Port:    8080,
		},
	}

	node, err := registry.RegisterNode(nodeReq)
	require.NoError(t, err)

	// Register services with same name but different versions
	for i := 1; i <= 2; i++ {
		serviceReq := &pkg.RegistrationRequest{
			Service: pkg.Service{
				Name:       "temperature-sensor", // Same name
				NodeID:     node.ID,
				Definition: "temperature-reading",
				URI:        fmt.Sprintf("/api/v%d/temperature", i),
				Method:     "GET",
				Version:    fmt.Sprintf("%d.0", i),
			},
		}

		_, err := registry.RegisterService(serviceReq)
		require.NoError(t, err)
	}

	// Find services by name
	services, err := registry.FindServicesByName("temperature-sensor")
	require.NoError(t, err)
	assert.Len(t, services, 2)

	// Verify both services have the same name but different versions
	versions := make(map[string]bool)
	for _, service := range services {
		assert.Equal(t, "temperature-sensor", service.Name)
		versions[service.Version] = true
	}

	assert.True(t, versions["1.0"])
	assert.True(t, versions["2.0"])
}

func TestRegistry_UnregisterNode(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Register a node
	req := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Test Node",
			Address: "localhost",
			Port:    8080,
		},
	}

	node, err := registry.RegisterNode(req)
	require.NoError(t, err)

	// Unregister the node
	err = registry.UnregisterNode(node.ID)
	require.NoError(t, err)

	// Verify node is removed
	_, err = registry.GetNode(node.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Node not found")
}

func TestRegistry_UnregisterNode_NotFound(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	err := registry.UnregisterNode("non-existent-node")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Node not found")
}

func TestRegistry_UnregisterService(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Setup node and service
	_, service := setupNodeAndService(t, registry)

	// Unregister the service
	err := registry.UnregisterService(service.ID)
	require.NoError(t, err)

	// Verify service is removed
	_, err = registry.GetService(service.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Service not found")
}

func TestRegistry_UnregisterService_NotFound(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	err := registry.UnregisterService("non-existent-service")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Service not found")
}

func TestRegistry_UpdateNodeHeartbeat(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Register a node
	req := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Test Node",
			Address: "localhost",
			Port:    8080,
		},
	}

	node, err := registry.RegisterNode(req)
	require.NoError(t, err)

	originalLastSeen := node.LastSeen

	// Wait a bit to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Update heartbeat
	err = registry.UpdateNodeHeartbeat(node.ID)
	require.NoError(t, err)

	// Verify last seen is updated
	updated, err := registry.GetNode(node.ID)
	require.NoError(t, err)
	assert.True(t, updated.LastSeen.After(originalLastSeen))
	assert.Equal(t, pkg.NodeStatusOnline, updated.Status)
}

func TestRegistry_UpdateNodeHeartbeat_NotFound(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	err := registry.UpdateNodeHeartbeat("non-existent-node")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Node not found")
}

func TestRegistry_UpdateServiceHealth(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Setup node and service
	_, service := setupNodeAndService(t, registry)

	originalLastSeen := service.LastSeen

	// Wait a bit to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Update service health
	err := registry.UpdateServiceHealth(service.ID, pkg.ServiceStatusUnhealthy)
	require.NoError(t, err)

	// Verify service is updated
	updated, err := registry.GetService(service.ID)
	require.NoError(t, err)
	assert.Equal(t, pkg.ServiceStatusUnhealthy, updated.Status)
	assert.True(t, updated.LastSeen.After(originalLastSeen))
}

func TestRegistry_UpdateServiceHealth_NotFound(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	err := registry.UpdateServiceHealth("non-existent-service", pkg.ServiceStatusUnhealthy)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Service not found")
}

func TestRegistry_CleanupInactiveNodes(t *testing.T) {
	registry, db := setupRegistryTest(t)

	// Create nodes with different last seen times
	oldTime := time.Now().Add(-2 * time.Hour)
	recentTime := time.Now().Add(-30 * time.Minute)

	// Register old node
	oldNode := &pkg.Node{
		ID:       "old-node",
		Name:     "Old Node",
		Address:  "localhost",
		Port:     8080,
		Status:   pkg.NodeStatusOnline,
		LastSeen: oldTime,
	}

	err := db.CreateNode(oldNode)
	require.NoError(t, err)

	// Register recent node
	recentNode := &pkg.Node{
		ID:       "recent-node",
		Name:     "Recent Node",
		Address:  "localhost",
		Port:     8081,
		Status:   pkg.NodeStatusOnline,
		LastSeen: recentTime,
	}

	err = db.CreateNode(recentNode)
	require.NoError(t, err)

	// Cleanup nodes inactive for more than 1 hour
	err = registry.CleanupInactiveNodes(1 * time.Hour)
	require.NoError(t, err)

	// Verify old node is marked offline
	oldUpdated, err := registry.GetNode("old-node")
	require.NoError(t, err)
	assert.Equal(t, pkg.NodeStatusOffline, oldUpdated.Status)

	// Verify recent node is still online
	recentUpdated, err := registry.GetNode("recent-node")
	require.NoError(t, err)
	assert.Equal(t, pkg.NodeStatusOnline, recentUpdated.Status)
}

func TestRegistry_GetMetrics(t *testing.T) {
	registry, _ := setupRegistryTest(t)

	// Setup multiple nodes and services
	for i := 1; i <= 2; i++ {
		nodeReq := &pkg.RegistrationRequest{
			Node: pkg.Node{
				Name:    fmt.Sprintf("Node %d", i),
				Address: "localhost",
				Port:    8080 + i,
			},
		}

		node, err := registry.RegisterNode(nodeReq)
		require.NoError(t, err)

		// Register service for each node
		serviceReq := &pkg.RegistrationRequest{
			Service: pkg.Service{
				Name:       fmt.Sprintf("service-%d", i),
				NodeID:     node.ID,
				Definition: fmt.Sprintf("definition-%d", i),
				URI:        fmt.Sprintf("/api/service%d", i),
				Method:     "GET",
			},
		}

		_, err = registry.RegisterService(serviceReq)
		require.NoError(t, err)
	}

	// Get metrics
	metrics, err := registry.GetMetrics()
	require.NoError(t, err)
	require.NotNil(t, metrics)

	assert.Equal(t, int64(2), metrics.TotalNodes)
	assert.Equal(t, int64(2), metrics.ActiveNodes) // Both should be online
	assert.Equal(t, int64(2), metrics.TotalServices)
	assert.Equal(t, int64(2), metrics.ActiveServices) // Both should be active
}

// Helper function to setup a node and service for testing
func setupNodeAndService(t *testing.T, registry *internal.Registry) (*pkg.Node, *pkg.Service) {
	// Register node
	nodeReq := &pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "Test Node",
			Address: "localhost",
			Port:    8080,
		},
	}

	node, err := registry.RegisterNode(nodeReq)
	require.NoError(t, err)

	// Register service
	serviceReq := &pkg.RegistrationRequest{
		Service: pkg.Service{
			Name:       "test-service",
			NodeID:     node.ID,
			Definition: "test-definition",
			URI:        "/api/test",
			Method:     "GET",
		},
	}

	service, err := registry.RegisterService(serviceReq)
	require.NoError(t, err)

	return node, service
}
