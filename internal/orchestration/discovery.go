package orchestration

import (
	"strings"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
)

// findMatchingServices discovers services based on name and filters
func (o *Orchestrator) findMatchingServices(serviceName string, filters map[string]interface{}) ([]*pkg.Service, error) {
	var services []*pkg.Service
	var err error

	if serviceName != "" {
		services, err = o.db.GetServicesByName(serviceName)
	} else {
		services, err = o.db.ListServices()
	}

	if err != nil {
		o.logger.WithError(err).Error("Failed to find services")
		return nil, pkg.DatabaseError(err)
	}

	filteredServices := make([]*pkg.Service, 0)
	for _, service := range services {
		if service.Status != pkg.ServiceStatusActive {
			continue
		}

		if o.matchesFilters(service, filters) {
			filteredServices = append(filteredServices, service)
		}
	}

	return filteredServices, nil
}

// matchesFilters checks if a service matches the given filter criteria
func (o *Orchestrator) matchesFilters(service *pkg.Service, filters map[string]interface{}) bool {
	if filters == nil {
		return true
	}

	for key, value := range filters {
		switch key {
		case "version":
			if versionStr, ok := value.(string); ok && service.Version != versionStr {
				return false
			}
		case "method":
			if methodStr, ok := value.(string); ok && !strings.EqualFold(service.Method, methodStr) {
				return false
			}
		case "definition":
			if defStr, ok := value.(string); ok && !strings.Contains(strings.ToLower(service.Definition), strings.ToLower(defStr)) {
				return false
			}
		case "metadata":
			if metadataMap, ok := value.(map[string]interface{}); ok {
				for metaKey, metaValue := range metadataMap {
					if serviceValue, exists := service.Metadata[metaKey]; !exists {
						return false
					} else if metaValueStr, ok := metaValue.(string); ok && serviceValue != metaValueStr {
						return false
					}
				}
			}
		}
	}

	return true
}

// buildCandidateList creates service candidates from matching services
func (o *Orchestrator) buildCandidateList(services []*pkg.Service, requester *pkg.Node, preferences map[string]interface{}) ([]*ServiceCandidate, error) {
	candidates := make([]*ServiceCandidate, 0, len(services))

	for _, service := range services {
		node, err := o.db.GetNode(service.NodeID)
		if err != nil {
			o.logger.WithError(err).WithField("node_id", service.NodeID).Error("Failed to get node for service")
			continue
		}

		if node == nil || node.Status != pkg.NodeStatusOnline {
			continue
		}

		candidate := &ServiceCandidate{
			Service: service,
			Node:    node,
		}

		candidate.Distance = o.calculateDistance(requester, node)
		candidate.Reliability = o.calculateReliability(service, node)
		candidate.Score = o.calculateScore(candidate, preferences)

		candidates = append(candidates, candidate)
	}

	return candidates, nil
}
