// Package handlers implements HTTP request handlers for the Arrowhead REST API.
//
// This package provides Gin-based HTTP handlers that implement the Arrowhead Framework 4.x
// REST API specification, including endpoints for:
//   - Service Registry (system/service registration and discovery)
//   - Authorization (rule management and access control)
//   - Orchestration (service matching and recommendations)
//   - Health checks and metrics
//
// All handlers use structured error responses and support both JSON input/output.
package handlers

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/auth"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/orchestration"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/registry"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// HTTP handlers
type Handlers struct {
	registry     *registry.Registry
	auth         *auth.AuthManager
	orchestrator *orchestration.Orchestrator
	logger       *logrus.Logger
}

func NewHandlers(
	reg *registry.Registry,
	authMgr *auth.AuthManager,
	orch *orchestration.Orchestrator,
	logger *logrus.Logger,
) *Handlers {
	return &Handlers{
		registry:     reg,
		auth:         authMgr,
		orchestrator: orch,
		logger:       logger,
	}
}

// Authenticate a request using mTLS client certificates.
func (h *Handlers) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if client certificate is present
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
				// A "Not Found" error is acceptable here, as it indicates a new system is trying to register.
				var appErr, ok = err.(*pkg.AppError)
				if !ok || (ok && appErr.Code != http.StatusNotFound) {
					h.logger.WithError(err).WithField("system_name", systemName).Error("Failed to lookup system")
					h.respondWithError(c, pkg.UnauthorizedError("System lookup failed"))
					return
				}
			}

			if system != nil {
				systemID = system.ID
			}
		}

		c.Set("is_admin", isAdmin)
		c.Set("system_name", systemName)
		c.Set("system_id", systemID)

		if isAdmin {
			h.logger.WithField("system", systemName).Debug("Admin authenticated via mTLS")
		} else {
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

// Handle POST /serviceregistry/mgmt/systems/batch
func (h *Handlers) RegisterSystemsBatch(c *gin.Context) {
	var reqs []pkg.SystemRegistration
	if err := c.ShouldBindJSON(&reqs); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid batch system registration request"))
		return
	}

	systems, err := h.registry.RegisterSystemsBatch(reqs)
	if err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusCreated, systems)
}

// Handle POST /serviceregistry/mgmt/systems
func (h *Handlers) RegisterSystem(c *gin.Context) {
	var req pkg.SystemRegistration
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid system registration request"))
		return
	}

	// Convert to internal format and register
	system, err := h.registry.RegisterSystem(&req)
	if err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in RegisterSystem")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusCreated, system)
}

// Handle POST /serviceregistry/register-system
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
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in RegisterSystemPublic")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusCreated, system)
}

// Handle DELETE /serviceregistry/mgmt/systems/:id
func (h *Handlers) UnregisterSystemByID(c *gin.Context) {
	systemIDStr := c.Param("id")
	systemID, err := strconv.Atoi(systemIDStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid system ID"))
		return
	}

	if err := h.registry.UnregisterSystemByID(systemID); err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in UnregisterSystemByID")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "System unregistered successfully"})
}

// Handle DELETE /serviceregistry/unregister-system
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
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in UnregisterSystemPublic")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "System unregistered successfully"})
}

// Handle GET /serviceregistry/mgmt/systems/:id
func (h *Handlers) GetSystemByID(c *gin.Context) {
	systemIDStr := c.Param("id")
	systemID, err := strconv.Atoi(systemIDStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid system ID"))
		return
	}

	system, err := h.registry.GetSystemByID(systemID)
	if err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in GetSystemByID")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusOK, system)
}

// Handle GET /serviceregistry/mgmt/systems
func (h *Handlers) ListSystems(c *gin.Context) {
	// Extract pagination and sorting parameters
	sortField := c.DefaultQuery("sort_field", "id")
	direction := c.DefaultQuery("direction", "ASC")

	systems, err := h.registry.ListSystemsWithParams(sortField, direction)
	if err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in ListSystems")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	response := pkg.SystemsResponse{
		Data:  systems,
		Count: len(systems),
	}

	c.JSON(http.StatusOK, response)
}

// Service Management Endpoints

// Handle POST /serviceregistry/mgmt
// TODO: What is the difference between this, RegisterSerivecesBatch and RegisterService?
func (h *Handlers) RegisterServiceMgmt(c *gin.Context) {
	var req pkg.ServiceRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid service registration request"))
		return
	}

	service, err := h.registry.RegisterService(&req)
	if err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in RegisterServiceMgmt")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusCreated, service)
}

// Handle POST /serviceregistry/mgmt/services/batch
func (h *Handlers) RegisterServicesBatch(c *gin.Context) {
	var reqs []pkg.ServiceRegistrationRequest
	if err := c.ShouldBindJSON(&reqs); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid batch service registration request"))
		return
	}

	services, err := h.registry.RegisterServicesBatch(reqs)
	if err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusCreated, services)
}

// Handle POST /serviceregistry/register
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
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in RegisterService")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusCreated, service)
}

// Handle DELETE /serviceregistry/mgmt/:id
func (h *Handlers) UnregisterServiceByID(c *gin.Context) {
	serviceIDStr := c.Param("id")
	serviceID, err := strconv.Atoi(serviceIDStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid service ID"))
		return
	}

	if err := h.registry.UnregisterServiceByID(serviceID); err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in UnregisterServiceByID")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Service unregistered successfully"})
}

// Handle DELETE /serviceregistry/unregister
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
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in UnregisterService")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Service unregistered successfully"})
}

// Handle GET /serviceregistry/mgmt/:id
func (h *Handlers) GetServiceByID(c *gin.Context) {
	serviceIDStr := c.Param("id")
	serviceID, err := strconv.Atoi(serviceIDStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid service ID"))
		return
	}

	service, err := h.registry.GetServiceByID(serviceID)
	if err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in GetServiceByID")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusOK, service)
}

// Handle GET /serviceregistry/mgmt
func (h *Handlers) ListServices(c *gin.Context) {
	// Extract pagination and sorting parameters
	sortField := c.DefaultQuery("sort_field", "id")
	direction := c.DefaultQuery("direction", "ASC")

	services, err := h.registry.ListServicesWithParams(sortField, direction)
	if err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in ListServices")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	response := pkg.ServicesResponse{
		Data:  services,
		Count: len(services),
	}

	c.JSON(http.StatusOK, response)
}

// Authorization Endpoints

// Handle POST /authorization/mgmt/intracloud/batch
func (h *Handlers) AddAuthorizationsBatch(c *gin.Context) {
	var reqs []pkg.AddAuthorizationRequest
	if err := c.ShouldBindJSON(&reqs); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid batch authorization request"))
		return
	}

	authorizations, err := h.registry.AddAuthorizationsBatch(reqs)
	if err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in AddAuthorizationsBatch")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	response := pkg.AuthorizationsResponse{
		Data:  authorizations,
		Count: len(authorizations),
	}

	c.JSON(http.StatusCreated, response)
}

// Handle POST /authorization/mgmt/intracloud
func (h *Handlers) AddAuthorization(c *gin.Context) {
	var req pkg.AddAuthorizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid authorization request"))
		return
	}

	authorizations, err := h.registry.AddAuthorization(&req)
	if err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in AddAuthorization")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	response := pkg.AuthorizationsResponse{
		Data:  authorizations,
		Count: len(authorizations),
	}

	c.JSON(http.StatusCreated, response)
}

// Handle DELETE /authorization/mgmt/intracloud/:id
func (h *Handlers) RemoveAuthorization(c *gin.Context) {
	authIDStr := c.Param("id")
	authID, err := strconv.Atoi(authIDStr)
	if err != nil {
		h.respondWithError(c, pkg.BadRequestError("Invalid authorization ID"))
		return
	}

	if err := h.registry.RemoveAuthorization(authID); err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in RemoveAuthorization")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Authorization removed successfully"})
}

// Handle GET /authorization/mgmt/intracloud
func (h *Handlers) ListAuthorizations(c *gin.Context) {
	// Extract pagination and sorting parameters
	sortField := c.DefaultQuery("sort_field", "id")
	direction := c.DefaultQuery("direction", "ASC")

	authorizations, err := h.registry.ListAuthorizationsWithParams(sortField, direction)
	if err != nil {
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in ListAuthorizations")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	response := pkg.AuthorizationsResponse{
		Data:  authorizations,
		Count: len(authorizations),
	}

	c.JSON(http.StatusOK, response)
}

// Orchestration Endpoints

// Handle POST /orchestrator/orchestration
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
		if appErr, ok := err.(*pkg.AppError); ok {
			h.respondWithError(c, appErr)
		} else {
			h.logger.WithError(err).Error("An unexpected error occurred in Orchestrate")
			h.respondWithError(c, pkg.InternalServerError("An unexpected internal error occurred"))
		}
		return
	}

	c.JSON(http.StatusOK, response)
}

// Health and utility endpoints

// Handle GET /health
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
