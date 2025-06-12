package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/api"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestSuite struct {
	router        *gin.Engine
	storage       internal.Database
	registry      *internal.Registry
	auth          *internal.AuthManager
	orchestrator  *internal.Orchestrator
	eventManager  *internal.EventManager
	healthChecker *internal.HealthChecker
	handlers      *handlers.Handlers
	logger        *logrus.Logger
}

func setupTestSuite(t *testing.T) *TestSuite {
	gin.SetMode(gin.TestMode)

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create temporary SQLite database for integration tests
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "integration_test.db")

	db, err := internal.NewStorage("sqlite", dbPath)
	require.NoError(t, err, "Failed to create SQLite database for integration test")

	registryService := internal.NewRegistry(db, logger)
	authManager := internal.NewAuthManager(db, logger, []byte("test-secret"))
	orchestratorService := internal.NewOrchestrator(db, logger)
	eventManager := internal.NewEventManager(db, logger)
	healthChecker := internal.NewHealthChecker(registryService, logger, time.Minute, 5*time.Minute, 10*time.Minute)

	// Create Gateway components for integration test (can be nil for basic tests)
	relayManager := internal.NewRelayManager(db, &internal.Config{}, logger)
	gatewaySecurityManager, _ := internal.NewGatewaySecurityManager(&internal.Config{}, logger)
	gatewayManager := internal.NewGatewayManager(db, &internal.Config{}, logger, relayManager, gatewaySecurityManager)

	h := handlers.New(registryService, authManager, orchestratorService, eventManager, gatewayManager, relayManager, logger)

	router := gin.New()
	router.Use(gin.Recovery())

	api := router.Group("/api/v1")

	registry := api.Group("/registry")
	{
		registry.POST("/nodes", h.RegisterNode)
		registry.GET("/nodes/:id", h.GetNode)
		registry.GET("/nodes", h.ListNodes)
		registry.POST("/services", h.AuthMiddleware(), h.RegisterService)
		registry.GET("/services/:id", h.GetService)
		registry.GET("/services", h.ListServices)
	}

	authRoutes := api.Group("/auth")
	{
		authRoutes.POST("/rules", h.AuthMiddleware(), h.CreateAuthRule)
		authRoutes.GET("/rules", h.ListAuthRules)
		authRoutes.POST("/token", h.AuthMiddleware(), h.GenerateToken)
	}

	orchestrationRoutes := api.Group("/orchestration")
	{
		orchestrationRoutes.POST("/", h.AuthMiddleware(), h.Orchestrate)
	}

	eventsRoutes := api.Group("/events")
	{
		eventsRoutes.POST("/publish", h.AuthMiddleware(), h.PublishEvent)
		eventsRoutes.POST("/subscribe", h.AuthMiddleware(), h.Subscribe)
		eventsRoutes.GET("/", h.ListEvents)
	}

	router.GET("/health", h.HealthCheck)
	router.GET("/api/v1/metrics", h.GetMetrics)

	t.Cleanup(func() {
		db.Close()
		eventManager.Close()
		healthChecker.Close()
		// Clean up temp database file
		os.Remove(dbPath)
	})

	return &TestSuite{
		router:        router,
		storage:       db,
		registry:      registryService,
		auth:          authManager,
		orchestrator:  orchestratorService,
		eventManager:  eventManager,
		healthChecker: healthChecker,
		handlers:      h,
		logger:        logger,
	}
}

func TestNodeRegistration(t *testing.T) {
	suite := setupTestSuite(t)

	node := pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "test-node",
			Address: "localhost",
			Port:    8080,
		},
	}

	reqBody, err := json.Marshal(node)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/registry/nodes", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response pkg.Node
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "test-node", response.Name)
	assert.Equal(t, "localhost", response.Address)
	assert.Equal(t, 8080, response.Port)
	assert.NotEmpty(t, response.ID)
}

func TestServiceRegistrationFlow(t *testing.T) {
	suite := setupTestSuite(t)

	node := pkg.RegistrationRequest{
		Node: pkg.Node{
			Name:    "provider-node",
			Address: "localhost",
			Port:    8080,
		},
	}

	reqBody, err := json.Marshal(node)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/registry/nodes", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	var nodeResponse pkg.Node
	err = json.Unmarshal(w.Body.Bytes(), &nodeResponse)
	require.NoError(t, err)

	token, err := suite.auth.GenerateAccessToken(nodeResponse.ID)
	require.NoError(t, err)

	service := pkg.RegistrationRequest{
		Service: pkg.Service{
			Name:       "temperature-sensor",
			Definition: "temperature-reading",
			URI:        "/api/temperature",
			Method:     "GET",
			NodeID:     nodeResponse.ID,
		},
	}

	serviceReqBody, err := json.Marshal(service)
	require.NoError(t, err)

	serviceReq := httptest.NewRequest("POST", "/api/v1/registry/services", bytes.NewBuffer(serviceReqBody))
	serviceReq.Header.Set("Content-Type", "application/json")
	serviceReq.Header.Set("Authorization", "Bearer "+token)
	serviceW := httptest.NewRecorder()

	suite.router.ServeHTTP(serviceW, serviceReq)
	assert.Equal(t, http.StatusCreated, serviceW.Code)

	var serviceResponse pkg.Service
	err = json.Unmarshal(serviceW.Body.Bytes(), &serviceResponse)
	require.NoError(t, err)

	assert.Equal(t, "temperature-sensor", serviceResponse.Name)
	assert.Equal(t, nodeResponse.ID, serviceResponse.NodeID)
}

func TestOrchestrationFlow(t *testing.T) {
	suite := setupTestSuite(t)

	consumerNode, providerNode, service := setupTestNodesAndService(t, suite)

	consumerToken, err := suite.auth.GenerateAccessToken(consumerNode.ID)
	require.NoError(t, err)

	authRule := pkg.AuthRequest{
		ConsumerID: consumerNode.ID,
		ProviderID: providerNode.ID,
		ServiceID:  service.ID,
	}

	authReqBody, err := json.Marshal(authRule)
	require.NoError(t, err)

	authReq := httptest.NewRequest("POST", "/api/v1/auth/rules", bytes.NewBuffer(authReqBody))
	authReq.Header.Set("Content-Type", "application/json")
	authReq.Header.Set("Authorization", "Bearer "+consumerToken)
	authW := httptest.NewRecorder()

	suite.router.ServeHTTP(authW, authReq)
	assert.Equal(t, http.StatusCreated, authW.Code)

	orchestrationReq := pkg.OrchestrationRequest{
		RequesterID: consumerNode.ID,
		ServiceName: "temperature-sensor",
	}

	orchReqBody, err := json.Marshal(orchestrationReq)
	require.NoError(t, err)

	orchReq := httptest.NewRequest("POST", "/api/v1/orchestration/", bytes.NewBuffer(orchReqBody))
	orchReq.Header.Set("Content-Type", "application/json")
	orchReq.Header.Set("Authorization", "Bearer "+consumerToken)
	orchW := httptest.NewRecorder()

	suite.router.ServeHTTP(orchW, orchReq)
	if orchW.Code != http.StatusOK {
		t.Logf("Response body: %s", orchW.Body.String())
		t.Logf("Response headers: %+v", orchW.Header())
	}
	assert.Equal(t, http.StatusOK, orchW.Code)

	var orchResponse pkg.OrchestrationResponse
	err = json.Unmarshal(orchW.Body.Bytes(), &orchResponse)
	require.NoError(t, err)

	assert.Len(t, orchResponse.Services, 1)
	assert.Equal(t, service.ID, orchResponse.Services[0].Service.ID)
}

func TestEventPublishingAndSubscription(t *testing.T) {
	suite := setupTestSuite(t)

	publisherNode := setupTestPublisher(t, suite)
	subscriberNode := setupTestSubscriber(t, suite)

	publisherToken, err := suite.auth.GenerateAccessToken(publisherNode.ID)
	require.NoError(t, err)

	subscriberToken, err := suite.auth.GenerateAccessToken(subscriberNode.ID)
	require.NoError(t, err)

	subscription := pkg.SubscriptionRequest{
		Topic:    "temperature",
		Endpoint: "http://localhost:8080/events",
	}

	subReqBody, err := json.Marshal(subscription)
	require.NoError(t, err)

	subReq := httptest.NewRequest("POST", "/api/v1/events/subscribe", bytes.NewBuffer(subReqBody))
	subReq.Header.Set("Content-Type", "application/json")
	subReq.Header.Set("Authorization", "Bearer "+subscriberToken)
	subW := httptest.NewRecorder()

	suite.router.ServeHTTP(subW, subReq)
	assert.Equal(t, http.StatusCreated, subW.Code)

	event := pkg.EventPublishRequest{
		Type:  "sensor-reading",
		Topic: "temperature",
		Payload: map[string]interface{}{
			"temperature": 23.5,
			"unit":        "celsius",
		},
	}

	eventReqBody, err := json.Marshal(event)
	require.NoError(t, err)

	eventReq := httptest.NewRequest("POST", "/api/v1/events/publish", bytes.NewBuffer(eventReqBody))
	eventReq.Header.Set("Content-Type", "application/json")
	eventReq.Header.Set("Authorization", "Bearer "+publisherToken)
	eventW := httptest.NewRecorder()

	suite.router.ServeHTTP(eventW, eventReq)
	assert.Equal(t, http.StatusCreated, eventW.Code)

	var eventResponse pkg.Event
	err = json.Unmarshal(eventW.Body.Bytes(), &eventResponse)
	require.NoError(t, err)

	assert.Equal(t, "sensor-reading", eventResponse.Type)
	assert.Equal(t, "temperature", eventResponse.Topic)
}

func TestHealthCheck(t *testing.T) {
	suite := setupTestSuite(t)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "healthy", response["status"])
}

func TestMetricsEndpoint(t *testing.T) {
	suite := setupTestSuite(t)

	setupTestNodesAndService(t, suite)

	req := httptest.NewRequest("GET", "/api/v1/metrics", nil)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var metrics pkg.Metrics
	err := json.Unmarshal(w.Body.Bytes(), &metrics)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, metrics.TotalNodes, int64(2))
	assert.GreaterOrEqual(t, metrics.TotalServices, int64(1))
}

func TestAuthenticationRequired(t *testing.T) {
	suite := setupTestSuite(t)

	service := pkg.RegistrationRequest{
		Service: pkg.Service{
			Name:       "test-service",
			Definition: "test-definition",
			URI:        "/test",
			Method:     "GET",
		},
	}

	reqBody, err := json.Marshal(service)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/registry/services", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func setupTestNodesAndService(t *testing.T, suite *TestSuite) (*pkg.Node, *pkg.Node, *pkg.Service) {
	consumer := &pkg.Node{
		Name:    "consumer-node",
		Address: "localhost",
		Port:    8081,
	}
	consumer, err := suite.registry.RegisterNode(&pkg.RegistrationRequest{Node: *consumer})
	require.NoError(t, err)

	provider := &pkg.Node{
		Name:    "provider-node",
		Address: "localhost",
		Port:    8082,
	}
	provider, err = suite.registry.RegisterNode(&pkg.RegistrationRequest{Node: *provider})
	require.NoError(t, err)

	service := &pkg.Service{
		Name:       "temperature-sensor",
		NodeID:     provider.ID,
		Definition: "temperature-reading",
		URI:        "/api/temperature",
		Method:     "GET",
	}
	service, err = suite.registry.RegisterService(&pkg.RegistrationRequest{Service: *service})
	require.NoError(t, err)

	return consumer, provider, service
}

func setupTestPublisher(t *testing.T, suite *TestSuite) *pkg.Node {
	publisher := &pkg.Node{
		Name:    "publisher-node",
		Address: "localhost",
		Port:    8083,
	}
	publisher, err := suite.registry.RegisterNode(&pkg.RegistrationRequest{Node: *publisher})
	require.NoError(t, err)

	return publisher
}

func setupTestSubscriber(t *testing.T, suite *TestSuite) *pkg.Node {
	subscriber := &pkg.Node{
		Name:    "subscriber-node",
		Address: "localhost",
		Port:    8084,
	}
	subscriber, err := suite.registry.RegisterNode(&pkg.RegistrationRequest{Node: *subscriber})
	require.NoError(t, err)

	return subscriber
}
