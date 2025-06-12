package health

import (
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// startCleanupWorker starts the periodic cleanup routine
func (hc *HealthChecker) startCleanupWorker() {
	ticker := time.NewTicker(hc.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-hc.ctx.Done():
			return
		case <-ticker.C:
			hc.performCleanup()
		}
	}
}

// performCleanup performs node and service cleanup tasks
func (hc *HealthChecker) performCleanup() {
	if err := hc.registry.CleanupInactiveNodes(hc.inactiveTimeout); err != nil {
		hc.logger.WithError(err).Error("Failed to cleanup inactive nodes")
	}

	nodes, err := hc.registry.ListNodes()
	if err != nil {
		hc.logger.WithError(err).Error("Failed to get nodes for cleanup")
		return
	}

	cutoff := time.Now().Add(-hc.inactiveTimeout)
	for _, node := range nodes {
		if node.LastSeen.Before(cutoff) {
			services, err := hc.registry.ListServicesByNode(node.ID)
			if err != nil {
				hc.logger.WithError(err).WithField("node_id", node.ID).Error("Failed to get services for cleanup")
				continue
			}

			for _, service := range services {
				if service.LastSeen.Before(cutoff) && service.Status == pkg.ServiceStatusActive {
					hc.registry.UpdateServiceHealth(service.ID, pkg.ServiceStatusInactive)
					hc.logger.WithFields(logrus.Fields{
						"service_id": service.ID,
						"node_id":    node.ID,
					}).Info("Marked service as inactive due to inactivity")
				}
			}
		}
	}

	hc.logger.Debug("Cleanup worker completed")
}
