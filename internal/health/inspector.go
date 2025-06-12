package health

import (
	"fmt"
	"net/http"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// performHealthChecks checks the health of all active services
func (hc *HealthChecker) performHealthChecks() {
	services, err := hc.registry.ListServices()
	if err != nil {
		hc.logger.WithError(err).Error("Failed to get services for health check")
		return
	}

	for _, service := range services {
		if service.HealthCheck != "" && service.Status == pkg.ServiceStatusActive {
			go hc.checkServiceHealth(service)
		}
	}
}

// checkServiceHealth performs a health check for a specific service
func (hc *HealthChecker) checkServiceHealth(service *pkg.Service) {
	node, err := hc.registry.GetNode(service.NodeID)
	if err != nil {
		hc.logger.WithError(err).WithField("service_id", service.ID).Error("Failed to get node for health check")
		return
	}

	if node == nil {
		hc.logger.WithField("service_id", service.ID).Warn("Node not found for health check")
		return
	}

	healthURL := service.HealthCheck
	if healthURL == "" {
		return
	}

	if healthURL[0] == '/' {
		healthURL = fmt.Sprintf("http://%s:%d%s", node.Address, node.Port, healthURL)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(healthURL)
	if err != nil {
		hc.logger.WithError(err).WithFields(logrus.Fields{
			"service_id": service.ID,
			"health_url": healthURL,
		}).Warn("Service health check failed")

		hc.registry.UpdateServiceHealth(service.ID, pkg.ServiceStatusUnhealthy)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		hc.registry.UpdateServiceHealth(service.ID, pkg.ServiceStatusHealthy)
		hc.logger.WithFields(logrus.Fields{
			"service_id": service.ID,
			"status":     resp.StatusCode,
		}).Debug("Service health check passed")
	} else {
		hc.registry.UpdateServiceHealth(service.ID, pkg.ServiceStatusUnhealthy)
		hc.logger.WithFields(logrus.Fields{
			"service_id": service.ID,
			"status":     resp.StatusCode,
			"health_url": healthURL,
		}).Warn("Service health check returned error status")
	}
}

// GetNodeHealth returns the health status of a specific node
func (hc *HealthChecker) GetNodeHealth(nodeID string) (*pkg.HealthStatus, error) {
	node, err := hc.registry.GetNode(nodeID)
	if err != nil {
		return nil, err
	}

	if node == nil {
		return &pkg.HealthStatus{
			Service:   "node-" + nodeID,
			Status:    "not_found",
			Timestamp: time.Now(),
		}, nil
	}

	health := &pkg.HealthStatus{
		Service:   "node-" + node.Name,
		Timestamp: time.Now(),
		Details:   make(map[string]string),
	}

	health.Details["address"] = node.Address
	health.Details["port"] = fmt.Sprintf("%d", node.Port)
	health.Details["last_seen"] = node.LastSeen.Format(time.RFC3339)

	if node.Status == pkg.NodeStatusOnline {
		lastSeenThreshold := time.Now().Add(-5 * time.Minute)
		if node.LastSeen.After(lastSeenThreshold) {
			health.Status = "healthy"
		} else {
			health.Status = "degraded"
			health.Details["reason"] = "not recently seen"
		}
	} else {
		health.Status = "unhealthy"
		health.Details["reason"] = "node offline"
	}

	return health, nil
}

// GetOverallHealth returns the overall health status of the node
func (hc *HealthChecker) GetOverallHealth() map[string]interface{} {
	metrics, err := hc.registry.GetMetrics()
	if err != nil {
		hc.logger.WithError(err).Error("Failed to get metrics for health overview")
		return map[string]interface{}{
			"status": "error",
			"error":  "Failed to get metrics",
		}
	}

	status := "healthy"
	if metrics.ActiveNodes == 0 {
		status = "degraded"
	}

	healthRatio := float64(metrics.ActiveNodes) / float64(metrics.TotalNodes)
	if healthRatio < 0.5 {
		status = "unhealthy"
	}

	return map[string]interface{}{
		"status":            status,
		"timestamp":         time.Now().Format(time.RFC3339),
		"total_nodes":       metrics.TotalNodes,
		"active_nodes":      metrics.ActiveNodes,
		"total_services":    metrics.TotalServices,
		"active_services":   metrics.ActiveServices,
		"health_ratio":      healthRatio,
		"health_percentage": int(healthRatio * 100),
	}
}
