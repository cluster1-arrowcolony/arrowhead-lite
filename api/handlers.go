package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/auth"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/events"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/gateway"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/orchestration"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/registry"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/relay"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// HTTP handlers for the Arrowhead IoT Service Mesh API.
type Handlers struct {
	registry       *registry.Registry
	auth           *auth.AuthManager
	orchestrator   *orchestration.Orchestrator
	eventManager   *events.EventManager
	gatewayManager *gateway.GatewayManager
	relayManager   *relay.RelayManager
	logger         *logrus.Logger
}

func New(
	reg *registry.Registry,
	authMgr *auth.AuthManager,
	orch *orchestration.Orchestrator,
	evtMgr *events.EventManager,
	gwMgr *gateway.GatewayManager,
	relayMgr *relay.RelayManager,
	logger *logrus.Logger,
) *Handlers {
	return &Handlers{
		registry:       reg,
		auth:           authMgr,
		orchestrator:   orch,
		eventManager:   evtMgr,
		gatewayManager: gwMgr,
		relayManager:   relayMgr,
		logger:         logger,
	}
}

// Authenticate a request before serving it.
func (h *Handlers) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			h.respondWithError(c, pkg.UnauthorizedError("Authorization header required"))
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			h.respondWithError(c, pkg.UnauthorizedError("Bearer token required"))
			return
		}

		claims, err := h.auth.ValidateToken(tokenString)
		if err != nil {
			h.respondWithError(c, err.(*pkg.AppError))
			return
		}

		// Set context based on token type
		if claims.IsAdmin {
			c.Set("is_admin", true)
			c.Set("admin_user", claims.AdminUser)
			c.Set("node_id", "") // Admin tokens don't have node_id
			c.Set("node_name", "Admin")
		} else {
			c.Set("is_admin", false)
			c.Set("node_id", claims.NodeID)
			c.Set("node_name", claims.NodeName)
		}
		c.Next() // Serve the request.
	}
}

// Register a new node.
func (h *Handlers) RegisterNode(c *gin.Context) {
	var req pkg.RegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	node, err := h.registry.RegisterNode(&req)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusCreated, node)
}

// Register a new service for a node.
func (h *Handlers) RegisterService(c *gin.Context) {
	var req pkg.RegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	if nodeID, exists := c.Get("node_id"); exists {
		if req.Service.NodeID == "" {
			req.Service.NodeID = nodeID.(string)
		}
	}

	service, err := h.registry.RegisterService(&req)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusCreated, service)
}

// Unregister a node or service.
func (h *Handlers) UnregisterNode(c *gin.Context) {
	nodeID := c.Param("id")
	if nodeID == "" {
		h.respondWithError(c, pkg.BadRequestError("Node ID required"))
		return
	}

	if err := h.registry.UnregisterNode(nodeID); err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Node unregistered successfully"})
}

// Unregister a service.
func (h *Handlers) UnregisterService(c *gin.Context) {
	serviceID := c.Param("id")
	if serviceID == "" {
		h.respondWithError(c, pkg.BadRequestError("Service ID required"))
		return
	}

	if err := h.registry.UnregisterService(serviceID); err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Service unregistered successfully"})
}

// Get details of a node.
func (h *Handlers) GetNode(c *gin.Context) {
	nodeID := c.Param("id")
	if nodeID == "" {
		h.respondWithError(c, pkg.BadRequestError("Node ID required"))
		return
	}

	node, err := h.registry.GetNode(nodeID)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, node)
}

// Get details of a service.
func (h *Handlers) GetService(c *gin.Context) {
	serviceID := c.Param("id")
	if serviceID == "" {
		h.respondWithError(c, pkg.BadRequestError("Service ID required"))
		return
	}

	service, err := h.registry.GetService(serviceID)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, service)
}

// List all registered nodes.
func (h *Handlers) ListNodes(c *gin.Context) {
	nodes, err := h.registry.ListNodes()
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"nodes": nodes})
}

// List all registered services, optionally filtered by node ID or name.
func (h *Handlers) ListServices(c *gin.Context) {
	nodeID := c.Query("node_id")
	name := c.Query("name")

	var services []*pkg.Service
	var err error

	if nodeID != "" {
		services, err = h.registry.ListServicesByNode(nodeID)
	} else if name != "" {
		services, err = h.registry.FindServicesByName(name)
	} else {
		services, err = h.registry.ListServices()
	}

	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"services": services})
}

// Create a new authorization rule.
func (h *Handlers) CreateAuthRule(c *gin.Context) {
	var req pkg.AuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	rule, err := h.auth.CreateAuthRule(&req)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusCreated, rule)
}

// Delete an existing authorization rule.
func (h *Handlers) DeleteAuthRule(c *gin.Context) {
	ruleID := c.Param("id")
	if ruleID == "" {
		h.respondWithError(c, pkg.BadRequestError("Rule ID required"))
		return
	}

	if err := h.auth.DeleteAuthRule(ruleID); err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Authorization rule deleted successfully"})
}

// List all authorization rules.
func (h *Handlers) ListAuthRules(c *gin.Context) {
	rules, err := h.auth.ListAuthRulesWithNames()
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

// Orchestrate a request to find services or nodes based on the provided criteria.
func (h *Handlers) Orchestrate(c *gin.Context) {
	var req pkg.OrchestrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	if nodeID, exists := c.Get("node_id"); exists {
		if req.RequesterID == "" {
			req.RequesterID = nodeID.(string)
		}
	}

	if req.RequesterID == "" {
		h.respondWithError(c, pkg.BadRequestError("Requester ID required"))
		return
	}

	response, err := h.orchestrator.Orchestrate(&req)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, response)
}

// Get service recommendations for a node based on its ID.
func (h *Handlers) GetServiceRecommendations(c *gin.Context) {
	nodeID := c.Param("node_id")
	if nodeID == "" {
		h.respondWithError(c, pkg.BadRequestError("Node ID required"))
		return
	}

	limitStr := c.DefaultQuery("limit", "10")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 10
	}

	recommendations, appErr := h.orchestrator.GetServiceRecommendations(nodeID, limit)
	if appErr != nil {
		h.respondWithError(c, appErr.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"recommendations": recommendations})
}

// Analyze the health of a service based on its ID.
func (h *Handlers) AnalyzeServiceHealth(c *gin.Context) {
	serviceID := c.Param("service_id")
	if serviceID == "" {
		h.respondWithError(c, pkg.BadRequestError("Service ID required"))
		return
	}

	health, err := h.orchestrator.AnalyzeServiceHealth(serviceID)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, health)
}

// Publish an event to the event manager.
func (h *Handlers) PublishEvent(c *gin.Context) {
	var req pkg.EventPublishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	publisherID, exists := c.Get("node_id")
	if !exists {
		h.respondWithError(c, pkg.UnauthorizedError("Publisher ID required"))
		return
	}

	event, err := h.eventManager.PublishEvent(&req, publisherID.(string))
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusCreated, event)
}

// Subscribe to events using a subscription request.
func (h *Handlers) Subscribe(c *gin.Context) {
	var req pkg.SubscriptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	subscriberID, exists := c.Get("node_id")
	if !exists {
		h.respondWithError(c, pkg.UnauthorizedError("Subscriber ID required"))
		return
	}

	subscription, err := h.eventManager.Subscribe(&req, subscriberID.(string))
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusCreated, subscription)
}

type Point struct {
	X float64
	Y float64
	Z float64
}

func (p *Point) XYZ() bool {
	return p.X >= 0 && p.Y >= 0
}

// Unsubscribe from an event subscription by ID.
func (h *Handlers) Unsubscribe(c *gin.Context) {
	subscriptionID := c.Param("id")
	if subscriptionID == "" {
		h.respondWithError(c, pkg.BadRequestError("Subscription ID required"))
		return
	}

	if err := h.eventManager.Unsubscribe(subscriptionID); err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Subscription removed successfully"})
}

// List all events published in the node, with an optional limit.
func (h *Handlers) ListEvents(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "100")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 100
	}

	events, appErr := h.eventManager.ListEvents(limit)
	if appErr != nil {
		h.respondWithError(c, appErr.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"events": events})
}

// List all event subscriptions in the node.
func (h *Handlers) ListSubscriptions(c *gin.Context) {
	subscriptions, err := h.eventManager.ListSubscriptions()
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"subscriptions": subscriptions})
}

// Retrieve node metrics.
func (h *Handlers) GetMetrics(c *gin.Context) {
	metrics, err := h.registry.GetMetrics()
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, metrics)
}

// Get health status of the service mesh.
func (h *Handlers) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": "2024-01-01T00:00:00Z",
		"version":   "1.0.0",
	})
}

// Get detailed health with percentage for dashboard
func (h *Handlers) GetDetailedHealth(c *gin.Context) {
	nodes, err := h.registry.ListNodes()
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	totalNodes := len(nodes)
	activeNodes := 0
	for _, node := range nodes {
		if node.Status == "active" {
			activeNodes++
		}
	}

	var healthPercentage int
	var healthRatio float64
	var status string
	if totalNodes == 0 {
		healthPercentage = 100
		healthRatio = 1.0
		status = "healthy"
	} else {
		healthPercentage = (activeNodes * 100) / totalNodes
		healthRatio = float64(activeNodes) / float64(totalNodes)
		if healthPercentage >= 80 {
			status = "healthy"
		} else if healthPercentage >= 50 {
			status = "degraded"
		} else {
			status = "unhealthy"
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":            status,
		"health_percentage": healthPercentage,
		"health_ratio":      healthRatio,
		"active_nodes":      activeNodes,
		"total_nodes":       totalNodes,
	})
}

// Create a new access token for the node.
func (h *Handlers) GenerateToken(c *gin.Context) {
	nodeID, exists := c.Get("node_id")
	if !exists {
		h.respondWithError(c, pkg.UnauthorizedError("Node ID required"))
		return
	}

	token, err := h.auth.GenerateAccessToken(nodeID.(string))
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   86400,
	})
}

// Update the heartbeat timestamp for a node.
func (h *Handlers) UpdateNodeHeartbeat(c *gin.Context) {
	nodeID, exists := c.Get("node_id")
	if !exists {
		h.respondWithError(c, pkg.UnauthorizedError("Node ID required"))
		return
	}

	if err := h.registry.UpdateNodeHeartbeat(nodeID.(string)); err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Heartbeat updated successfully"})
}

// Administrative login endpoint (doesn't require node registration)
func (h *Handlers) AdminLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	// Simple admin validation (in production, this would validate against proper credentials)
	if req.Username != "admin" {
		h.respondWithError(c, pkg.UnauthorizedError("Invalid credentials"))
		return
	}

	// Generate admin token
	token, err := h.auth.GenerateAdminToken(req.Username)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   86400,
		"admin_user":   req.Username,
		"is_admin":     true,
	})
}

// Login endpoint for dashboard authentication (legacy - node-based)
func (h *Handlers) Login(c *gin.Context) {
	var req struct {
		NodeName string `json:"node_name" binding:"required"`
		Password string `json:"password,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	// Find node by name
	nodes, err := h.registry.ListNodes()
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	var node *pkg.Node
	for _, s := range nodes {
		if s.Name == req.NodeName {
			node = s
			break
		}
	}

	if node == nil {
		h.respondWithError(c, pkg.UnauthorizedError("Node not found"))
		return
	}

	// Generate token for this node
	token, err := h.auth.GenerateAccessToken(node.ID)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   86400,
		"node_id":      node.ID,
		"node_name":    node.Name,
	})
}

// ===== GATEWAY API ENDPOINTS =====

// Register a new gateway for inter-cloud communication
func (h *Handlers) RegisterGateway(c *gin.Context) {
	var req pkg.GatewayRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	if err := h.gatewayManager.RegisterGateway(&req.Gateway); err != nil {
		h.respondWithError(c, pkg.InternalServerError("Failed to register gateway: "+err.Error()))
		return
	}

	c.JSON(http.StatusCreated, req.Gateway)
}

// Create a new gateway tunnel
func (h *Handlers) CreateTunnel(c *gin.Context) {
	gatewayID := c.Param("id")
	if gatewayID == "" {
		h.respondWithError(c, pkg.BadRequestError("Gateway ID required"))
		return
	}

	var req pkg.TunnelCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	tunnel, err := h.gatewayManager.CreateTunnel(gatewayID, &req)
	if err != nil {
		h.respondWithError(c, pkg.InternalServerError("Failed to create tunnel: "+err.Error()))
		return
	}

	c.JSON(http.StatusCreated, tunnel)
}

// Create a new gateway session
func (h *Handlers) CreateGatewaySession(c *gin.Context) {
	tunnelID := c.Param("tunnel_id")
	if tunnelID == "" {
		h.respondWithError(c, pkg.BadRequestError("Tunnel ID required"))
		return
	}

	var req struct {
		RequesterID string `json:"requester_id" binding:"required"`
		ProviderID  string `json:"provider_id" binding:"required"`
		ServiceID   string `json:"service_id" binding:"required"`
		Duration    int    `json:"duration"` // Duration in seconds, default 3600 (1 hour)
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	if req.Duration <= 0 {
		req.Duration = 3600 // Default 1 hour
	}

	session, err := h.gatewayManager.CreateSession(
		tunnelID,
		req.RequesterID,
		req.ProviderID,
		req.ServiceID,
		time.Duration(req.Duration)*time.Second,
	)
	if err != nil {
		h.respondWithError(c, pkg.InternalServerError("Failed to create session: "+err.Error()))
		return
	}

	c.JSON(http.StatusCreated, session)
}

// Route a message through the gateway node
func (h *Handlers) RouteGatewayMessage(c *gin.Context) {
	var message pkg.GatewayMessage
	if err := c.ShouldBindJSON(&message); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	if err := h.gatewayManager.RouteMessage(&message); err != nil {
		h.respondWithError(c, pkg.InternalServerError("Failed to route message: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Message routed successfully"})
}

// Validate a gateway session token
func (h *Handlers) ValidateGatewaySession(c *gin.Context) {
	sessionToken := c.Param("token")
	if sessionToken == "" {
		h.respondWithError(c, pkg.BadRequestError("Session token required"))
		return
	}

	session, err := h.gatewayManager.ValidateSession(sessionToken)
	if err != nil {
		h.respondWithError(c, pkg.UnauthorizedError("Invalid session token: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, session)
}

// Get gateway details by ID
func (h *Handlers) GetGateway(c *gin.Context) {
	gatewayID := c.Param("id")
	if gatewayID == "" {
		h.respondWithError(c, pkg.BadRequestError("Gateway ID required"))
		return
	}

	gateway, err := h.gatewayManager.GetGateway(gatewayID)
	if err != nil {
		h.respondWithError(c, pkg.NotFoundError("Gateway not found: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, gateway)
}

// List all registered gateways
func (h *Handlers) ListGateways(c *gin.Context) {
	gateways := h.gatewayManager.ListGateways()
	c.JSON(http.StatusOK, gin.H{"gateways": gateways})
}

// List tunnels for a specific gateway
func (h *Handlers) ListTunnels(c *gin.Context) {
	gatewayID := c.Param("id")
	if gatewayID == "" {
		h.respondWithError(c, pkg.BadRequestError("Gateway ID required"))
		return
	}

	tunnels := h.gatewayManager.ListTunnels(gatewayID)
	c.JSON(http.StatusOK, gin.H{"tunnels": tunnels})
}

// Close a gateway session
func (h *Handlers) CloseGatewaySession(c *gin.Context) {
	sessionID := c.Param("session_id")
	if sessionID == "" {
		h.respondWithError(c, pkg.BadRequestError("Session ID required"))
		return
	}

	if err := h.gatewayManager.CloseSession(sessionID); err != nil {
		h.respondWithError(c, pkg.InternalServerError("Failed to close session: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Session closed successfully"})
}

// Create a relay connection for a gateway
func (h *Handlers) CreateRelayConnection(c *gin.Context) {
	gatewayID := c.Param("id")
	if gatewayID == "" {
		h.respondWithError(c, pkg.BadRequestError("Gateway ID required"))
		return
	}

	var req pkg.RelayConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	// Validate the relay manager is available
	if h.relayManager == nil {
		h.respondWithError(c, pkg.InternalServerError("Relay manager not available"))
		return
	}

	// Create relay connection through relay manager
	relayConnection, err := h.relayManager.CreateRelayConnection(gatewayID, &req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create relay connection")
		h.respondWithError(c, pkg.InternalServerError("Failed to create relay connection"))
		return
	}

	h.logger.WithFields(logrus.Fields{
		"gateway_id":    gatewayID,
		"connection_id": relayConnection.ID,
		"broker_type":   req.BrokerType,
		"broker_url":    req.BrokerURL,
	}).Info("Relay connection created successfully")

	c.JSON(http.StatusCreated, gin.H{
		"message":       "Relay connection created successfully",
		"connection_id": relayConnection.ID,
		"gateway_id":    gatewayID,
		"connection":    relayConnection,
	})
}

// Gateway orchestration for inter-cloud service discovery
func (h *Handlers) GatewayOrchestrate(c *gin.Context) {
	var req pkg.GatewayOrchestrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid request body"))
		return
	}

	// Validate required fields
	if req.RequesterID == "" {
		h.respondWithError(c, pkg.BadRequestError("Requester ID is required"))
		return
	}
	if req.ServiceName == "" {
		h.respondWithError(c, pkg.BadRequestError("Service name is required"))
		return
	}
	if req.TargetCloudID == "" {
		h.respondWithError(c, pkg.BadRequestError("Target cloud ID is required"))
		return
	}

	// Check if gateway manager is available
	if h.gatewayManager == nil {
		h.respondWithError(c, pkg.InternalServerError("Gateway manager not available"))
		return
	}

	// First, try to find services locally
	localServices, err := h.orchestrator.Orchestrate(&pkg.OrchestrationRequest{
		RequesterID: req.RequesterID,
		ServiceName: req.ServiceName,
		Filters:     req.Filters,
		Preferences: req.Preferences,
	})

	if err == nil && len(localServices.Services) > 0 {
		// Service found locally, return local orchestration result
		service := localServices.Services[0]
		response := pkg.GatewayOrchestrationResponse{
			TunnelID:     "local",
			SessionID:    "local-session-" + strconv.FormatInt(time.Now().Unix(), 10),
			SessionToken: "local-token-" + req.RequesterID,
			Service:      service,
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		}
		c.JSON(http.StatusOK, response)
		return
	}

	// Service not found locally, attempt inter-cloud orchestration
	// Create tunnel request for the target cloud
	tunnelRequest := &pkg.TunnelCreateRequest{
		Name:            "tunnel-" + req.TargetCloudID + "-" + req.ServiceName,
		RemoteGatewayID: req.TargetCloudID,
		Protocol:        pkg.TunnelProtocolHTTPS,
		EncryptionType:  "TLS",
	}

	tunnel, err := h.gatewayManager.CreateTunnel("", tunnelRequest)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"requester_id":    req.RequesterID,
			"service_name":    req.ServiceName,
			"target_cloud_id": req.TargetCloudID,
		}).Error("Failed to establish inter-cloud tunnel")
		h.respondWithError(c, pkg.InternalServerError("Failed to establish inter-cloud connection"))
		return
	}

	// Create session for inter-cloud access
	sessionToken, err := h.auth.GenerateAccessToken(req.RequesterID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to generate session token")
		h.respondWithError(c, pkg.InternalServerError("Failed to generate session token"))
		return
	}

	// Try to get remote gateway information
	remoteGateway, err := h.gatewayManager.GetGateway(req.TargetCloudID)
	if err != nil {
		h.logger.WithError(err).Warn("Could not get remote gateway information, using placeholder")
		// Create placeholder gateway if we can't find the remote one
		remoteGateway = &pkg.Gateway{
			ID:      req.TargetCloudID,
			Name:    "Remote Gateway - " + req.TargetCloudID,
			CloudID: req.TargetCloudID,
			Status:  pkg.GatewayStatusOnline,
		}
	}

	// Create session ID
	sessionID := "session-" + strconv.FormatInt(time.Now().Unix(), 10)

	response := pkg.GatewayOrchestrationResponse{
		TunnelID:      tunnel.ID,
		SessionID:     sessionID,
		SessionToken:  sessionToken,
		RemoteGateway: *remoteGateway,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	h.logger.WithFields(logrus.Fields{
		"requester_id":    req.RequesterID,
		"service_name":    req.ServiceName,
		"target_cloud_id": req.TargetCloudID,
		"tunnel_id":       tunnel.ID,
		"session_id":      sessionID,
	}).Info("Inter-cloud orchestration completed successfully")

	c.JSON(http.StatusOK, response)
}

// Format and send an error response to the client.
func (h *Handlers) respondWithError(c *gin.Context, err *pkg.AppError) {
	h.logger.WithFields(logrus.Fields{
		"error":  err.Message,
		"code":   err.Code,
		"path":   c.Request.URL.Path,
		"method": c.Request.Method,
	}).Error("Request failed")

	c.JSON(err.Code, gin.H{
		"error":   err.Message,
		"details": err.Details,
		"code":    err.Code,
	})
	c.Abort() // Stop further middleware and handlers from executing
}
