package handlers

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/auth"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/ca"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/orchestration"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/registry"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// HTTP handlers for the Arrowhead 4.x compatible API.
type Handlers struct {
	registry     *registry.Registry
	auth         *auth.AuthManager
	orchestrator *orchestration.Orchestrator
	ca           *ca.CertificateAuthority
	logger       *logrus.Logger
}

func New(
	reg *registry.Registry,
	authMgr *auth.AuthManager,
	orch *orchestration.Orchestrator,
	certificateAuthority *ca.CertificateAuthority,
	logger *logrus.Logger,
) *Handlers {
	return &Handlers{
		registry:     reg,
		auth:         authMgr,
		orchestrator: orch,
		ca:           certificateAuthority,
		logger:       logger,
	}
}

// Authenticate a request using mTLS client certificates.
func (h *Handlers) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if TLS is enabled and client certificate is present
		if c.Request.TLS == nil {
			h.respondWithError(c, pkg.UnauthorizedError("TLS required for authentication"))
			return
		}

		if len(c.Request.TLS.PeerCertificates) == 0 {
			h.respondWithError(c, pkg.UnauthorizedError("Client certificate required"))
			return
		}

		// Extract client certificate
		clientCert := c.Request.TLS.PeerCertificates[0]

		// Extract system name from certificate Common Name
		systemName := clientCert.Subject.CommonName
		if systemName == "" {
			h.respondWithError(c, pkg.UnauthorizedError("Invalid client certificate: missing Common Name"))
			return
		}

		// Check if this is a sysop (system operator) certificate
		isAdmin := strings.ToLower(systemName) == "sysop" || strings.Contains(strings.ToLower(systemName), "sysop")

		var systemID int
		if !isAdmin {
			// Look up the system ID from the database
			system, err := h.registry.GetSystemByName(systemName)
			if err != nil {
				h.logger.WithError(err).WithField("system_name", systemName).Error("Failed to lookup system")
				h.respondWithError(c, pkg.UnauthorizedError("System not found"))
				return
			}
			if system == nil {
				h.logger.WithField("system_name", systemName).Warn("System not registered")
				h.respondWithError(c, pkg.UnauthorizedError("System not registered"))
				return
			}
			systemID = system.ID
		}

		// Set context for the request
		if isAdmin {
			c.Set("is_admin", true)
			c.Set("system_name", systemName)
			c.Set("system_id", 0)
			h.logger.WithField("system", systemName).Debug("Admin authenticated via mTLS")
		} else {
			c.Set("is_admin", false)
			c.Set("system_name", systemName)
			c.Set("system_id", systemID)
			h.logger.WithFields(logrus.Fields{
				"system":    systemName,
				"system_id": systemID,
			}).Debug("System authenticated via mTLS")
		}

		// Store the authentication info (base64 encoded certificate)
		authInfo := base64.StdEncoding.EncodeToString(clientCert.Raw)
		c.Set("authentication_info", authInfo)
		c.Set("client_certificate", clientCert)

		c.Next()
	}
}

// System Management Endpoints

// RegisterSystem handles POST /serviceregistry/mgmt/systems
func (h *Handlers) RegisterSystem(c *gin.Context) {
	var req pkg.SystemRegistration
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid system registration request"))
		return
	}

	// Convert to internal format and register
	system, err := h.registry.RegisterSystem(&req)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusCreated, system)
}

// RegisterSystemPublic handles POST /serviceregistry/register-system
func (h *Handlers) RegisterSystemPublic(c *gin.Context) {
	var req pkg.SystemRegistration
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid system registration request"))
		return
	}

	// For public registration, extract authentication info from client certificate
	if authInfo, exists := c.Get("authentication_info"); exists {
		req.AuthenticationInfo = authInfo.(string)
	}

	system, err := h.registry.RegisterSystem(&req)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusCreated, system)
}

// RegisterSystemWithCertificate handles POST /serviceregistry/mgmt/systems with certificate signing
// This endpoint can be used by the SDK when it needs a new certificate for a system
func (h *Handlers) RegisterSystemWithCertificate(c *gin.Context) {
	var req pkg.SystemRegistration
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid system registration request"))
		return
	}

	h.logger.WithFields(logrus.Fields{
		"system_name": req.SystemName,
		"address":     req.Address,
		"port":        req.Port,
	}).Info("Registering system with certificate signing")

	// Register the system first
	system, err := h.registry.RegisterSystem(&req)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	// Sign a certificate for this system if CA is available
	var certificateData []byte
	if h.ca != nil {
		certificateData, err = h.ca.SignSystemCertificate(req.SystemName, req.Address, req.Port)
		if err != nil {
			h.logger.WithError(err).Warn("Failed to sign certificate for system")
			// Continue without certificate - just log the warning
		} else {
			h.logger.WithField("system_name", req.SystemName).Info("Certificate signed for system")
		}
	}

	// Create response
	response := map[string]interface{}{
		"system": system,
	}

	// Add certificate to response if available
	if certificateData != nil {
		response["certificate"] = base64.StdEncoding.EncodeToString(certificateData)
		response["certificate_format"] = "pkcs12"
	}

	c.JSON(http.StatusCreated, response)
}

// UnregisterSystemByID handles DELETE /serviceregistry/mgmt/systems/:id
func (h *Handlers) UnregisterSystemByID(c *gin.Context) {
	systemIDStr := c.Param("id")
	systemID, err := strconv.Atoi(systemIDStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid system ID"))
		return
	}

	if err := h.registry.UnregisterSystemByID(systemID); err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "System unregistered successfully"})
}

// UnregisterSystemPublic handles DELETE /serviceregistry/unregister-system
func (h *Handlers) UnregisterSystemPublic(c *gin.Context) {
	systemName := c.Query("system_name")
	address := c.Query("address")
	portStr := c.Query("port")

	if systemName == "" || address == "" || portStr == "" {
		h.respondWithError(c, pkg.BadRequestError("system_name, address, and port query parameters required"))
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid port"))
		return
	}

	if err := h.registry.UnregisterSystemByParams(systemName, address, port); err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "System unregistered successfully"})
}

// GetSystemByID handles GET /serviceregistry/mgmt/systems/:id
func (h *Handlers) GetSystemByID(c *gin.Context) {
	systemIDStr := c.Param("id")
	systemID, err := strconv.Atoi(systemIDStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid system ID"))
		return
	}

	system, err := h.registry.GetSystemByID(systemID)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, system)
}

// ListSystems handles GET /serviceregistry/mgmt/systems
func (h *Handlers) ListSystems(c *gin.Context) {
	// Extract pagination and sorting parameters
	sortField := c.DefaultQuery("sort_field", "id")
	direction := c.DefaultQuery("direction", "ASC")

	systems, err := h.registry.ListSystemsWithParams(sortField, direction)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	response := pkg.SystemsResponse{
		Data:  systems,
		Count: len(systems),
	}

	c.JSON(http.StatusOK, response)
}

// Service Management Endpoints

// RegisterServiceMgmt handles POST /serviceregistry/mgmt
func (h *Handlers) RegisterServiceMgmt(c *gin.Context) {
	var req pkg.ServiceRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid service registration request"))
		return
	}

	service, err := h.registry.RegisterServiceMgmt(&req)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusCreated, service)
}

// RegisterService handles POST /serviceregistry/register
func (h *Handlers) RegisterService(c *gin.Context) {
	var req pkg.ServiceRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid service registration request"))
		return
	}

	// Fill in provider system info from authenticated client
	if systemName, exists := c.Get("system_name"); exists {
		req.ProviderSystem.SystemName = systemName.(string)
	}
	if authInfo, exists := c.Get("authentication_info"); exists {
		req.ProviderSystem.AuthenticationInfo = authInfo.(string)
	}

	service, err := h.registry.RegisterService(&req)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusCreated, service)
}

// UnregisterServiceByID handles DELETE /serviceregistry/mgmt/:id
func (h *Handlers) UnregisterServiceByID(c *gin.Context) {
	serviceIDStr := c.Param("id")
	serviceID, err := strconv.Atoi(serviceIDStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid service ID"))
		return
	}

	if err := h.registry.UnregisterServiceByID(serviceID); err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Service unregistered successfully"})
}

// UnregisterService handles DELETE /serviceregistry/unregister
func (h *Handlers) UnregisterService(c *gin.Context) {
	systemName := c.Query("system_name")
	serviceURI := c.Query("service_uri")
	serviceDefinition := c.Query("service_definition")
	address := c.Query("address")
	portStr := c.Query("port")

	if systemName == "" || serviceURI == "" || serviceDefinition == "" || address == "" || portStr == "" {
		h.respondWithError(c, pkg.BadRequestError("system_name, service_uri, service_definition, address, and port query parameters required"))
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid port"))
		return
	}

	if err := h.registry.UnregisterServiceByParams(systemName, serviceURI, serviceDefinition, address, port); err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Service unregistered successfully"})
}

// GetServiceByID handles GET /serviceregistry/mgmt/:id
func (h *Handlers) GetServiceByID(c *gin.Context) {
	serviceIDStr := c.Param("id")
	serviceID, err := strconv.Atoi(serviceIDStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid service ID"))
		return
	}

	service, err := h.registry.GetServiceByID(serviceID)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, service)
}

// ListServices handles GET /serviceregistry/mgmt
func (h *Handlers) ListServices(c *gin.Context) {
	// Extract pagination and sorting parameters
	sortField := c.DefaultQuery("sort_field", "id")
	direction := c.DefaultQuery("direction", "ASC")

	services, err := h.registry.ListServicesWithParams(sortField, direction)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	response := pkg.ServicesResponse{
		Data:  services,
		Count: len(services),
	}

	c.JSON(http.StatusOK, response)
}

// Authorization Endpoints

// AddAuthorization handles POST /authorization/mgmt/intracloud
func (h *Handlers) AddAuthorization(c *gin.Context) {
	var req pkg.AddAuthorizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid authorization request"))
		return
	}

	authorization, err := h.registry.AddAuthorization(&req)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	// Return as AuthorizationsResponse with single item
	response := pkg.AuthorizationsResponse{
		Data:  []pkg.Authorization{*authorization},
		Count: 1,
	}

	c.JSON(http.StatusCreated, response)
}

// RemoveAuthorization handles DELETE /authorization/mgmt/intracloud/:id
func (h *Handlers) RemoveAuthorization(c *gin.Context) {
	authIDStr := c.Param("id")
	authID, err := strconv.Atoi(authIDStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid authorization ID"))
		return
	}

	if err := h.registry.RemoveAuthorization(authID); err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Authorization removed successfully"})
}

// ListAuthorizations handles GET /authorization/mgmt/intracloud
func (h *Handlers) ListAuthorizations(c *gin.Context) {
	// Extract pagination and sorting parameters
	sortField := c.DefaultQuery("sort_field", "id")
	direction := c.DefaultQuery("direction", "ASC")

	authorizations, err := h.registry.ListAuthorizationsWithParams(sortField, direction)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	response := pkg.AuthorizationsResponse{
		Data:  authorizations,
		Count: len(authorizations),
	}

	c.JSON(http.StatusOK, response)
}

// Orchestration Endpoints

// Orchestrate handles POST /orchestrator/orchestration
func (h *Handlers) Orchestrate(c *gin.Context) {
	var req pkg.OrchestrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid orchestration request"))
		return
	}

	// Fill in requester system info from authenticated client if not provided
	if req.RequesterSystem.SystemName == "" {
		if systemName, exists := c.Get("system_name"); exists {
			req.RequesterSystem.SystemName = systemName.(string)
		}
	}
	if req.RequesterSystem.AuthenticationInfo == "" {
		if authInfo, exists := c.Get("authentication_info"); exists {
			req.RequesterSystem.AuthenticationInfo = authInfo.(string)
		}
	}

	response, err := h.orchestrator.Orchestrate(&req)
	if err != nil {
		h.respondWithError(c, err.(*pkg.AppError))
		return
	}

	c.JSON(http.StatusOK, response)
}

// Health and utility endpoints

// HealthCheck handles GET /health
func (h *Handlers) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"service":   "arrowhead-lite",
	})
}

// Helper method to respond with errors
func (h *Handlers) respondWithError(c *gin.Context, err *pkg.AppError) {
	h.logger.WithFields(logrus.Fields{
		"error":      err.Message,
		"error_type": err.Type,
		"path":       c.Request.URL.Path,
		"method":     c.Request.Method,
	}).Error("API error")

	c.JSON(err.StatusCode(), gin.H{
		"error":   err.Type,
		"message": err.Message,
	})
}
