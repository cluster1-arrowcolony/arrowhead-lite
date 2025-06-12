package orchestration

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

type Orchestrator struct {
	db     Database
	logger *logrus.Logger
}

func newOrchestrator(db Database, logger *logrus.Logger) *Orchestrator {
	return &Orchestrator{
		db:     db,
		logger: logger,
	}
}

// Orchestrate performs service orchestration for a given request
func (o *Orchestrator) Orchestrate(req *pkg.OrchestrationRequest) (*pkg.OrchestrationResponse, error) {
	requester, err := o.db.GetNode(req.RequesterID)
	if err != nil {
		o.logger.WithError(err).Error("Failed to get requester node")
		return nil, pkg.DatabaseError(err)
	}

	if requester == nil {
		return nil, pkg.NotFoundError("Requester node not found")
	}

	services, err := o.findMatchingServices(req.ServiceName, req.Filters)
	if err != nil {
		return nil, err
	}

	if len(services) == 0 {
		return &pkg.OrchestrationResponse{Services: []pkg.ServiceResponse{}}, nil
	}

	candidates, err := o.buildCandidateList(services, requester, req.Preferences)
	if err != nil {
		return nil, err
	}

	rankedCandidates := o.rankCandidates(candidates, req.Preferences)

	serviceResponses := make([]pkg.ServiceResponse, 0, len(rankedCandidates))
	for _, candidate := range rankedCandidates {
		endpoint := fmt.Sprintf("https://%s:%d%s", candidate.Node.Address, candidate.Node.Port, candidate.Service.URI)

		serviceResponse := pkg.ServiceResponse{
			Service:  *candidate.Service,
			Node:     *candidate.Node,
			Endpoint: endpoint,
			Metadata: candidate.Service.Metadata,
		}

		serviceResponses = append(serviceResponses, serviceResponse)
	}

	o.logger.WithFields(logrus.Fields{
		"requester_id": req.RequesterID,
		"service_name": req.ServiceName,
		"candidates":   len(candidates),
		"returned":     len(serviceResponses),
	}).Info("Orchestration completed")

	return &pkg.OrchestrationResponse{Services: serviceResponses}, nil
}

// GetServiceRecommendations provides service recommendations for a node
func (o *Orchestrator) GetServiceRecommendations(nodeID string, limit int) ([]*pkg.Service, error) {
	node, err := o.db.GetNode(nodeID)
	if err != nil {
		o.logger.WithError(err).Error("Failed to get node for recommendations")
		return nil, pkg.DatabaseError(err)
	}

	if node == nil {
		return nil, pkg.NotFoundError("Node not found")
	}

	services, err := o.db.ListServices()
	if err != nil {
		o.logger.WithError(err).Error("Failed to get services for recommendations")
		return nil, pkg.DatabaseError(err)
	}

	recommendations := make([]*pkg.Service, 0)
	for _, service := range services {
		if service.Status == pkg.ServiceStatusActive && service.NodeID != nodeID {
			recommendations = append(recommendations, service)
		}
	}

	sort.Slice(recommendations, func(i, j int) bool {
		return recommendations[i].LastSeen.After(recommendations[j].LastSeen)
	})

	if len(recommendations) > limit {
		recommendations = recommendations[:limit]
	}

	return recommendations, nil
}

// GetServiceDependencies retrieves dependencies for a given service
func (o *Orchestrator) GetServiceDependencies(serviceID string) ([]*pkg.Service, error) {
	service, err := o.db.GetService(serviceID)
	if err != nil {
		o.logger.WithError(err).Error("Failed to get service for dependencies")
		return nil, pkg.DatabaseError(err)
	}

	if service == nil {
		return nil, pkg.NotFoundError("Service not found")
	}

	dependencies := make([]*pkg.Service, 0)

	if service.Metadata != nil {
		if deps, exists := service.Metadata["dependencies"]; exists {
			depNames := strings.Split(deps, ",")
			for _, depName := range depNames {
				depName = strings.TrimSpace(depName)
				if depName != "" {
					depServices, err := o.db.GetServicesByName(depName)
					if err != nil {
						o.logger.WithError(err).WithField("dependency", depName).Warn("Failed to get dependency service")
						continue
					}
					dependencies = append(dependencies, depServices...)
				}
			}
		}
	}

	return dependencies, nil
}

// AnalyzeServiceHealth performs health analysis for a given service
func (o *Orchestrator) AnalyzeServiceHealth(serviceID string) (*pkg.HealthStatus, error) {
	service, err := o.db.GetService(serviceID)
	if err != nil {
		o.logger.WithError(err).Error("Failed to get service for health analysis")
		return nil, pkg.DatabaseError(err)
	}

	if service == nil {
		return nil, pkg.NotFoundError("Service not found")
	}

	node, err := o.db.GetNode(service.NodeID)
	if err != nil {
		o.logger.WithError(err).Error("Failed to get node for health analysis")
		return nil, pkg.DatabaseError(err)
	}

	health := &pkg.HealthStatus{
		Service:   service.Name,
		Timestamp: time.Now(),
		Details:   make(map[string]string),
	}

	if node == nil {
		health.Status = "unhealthy"
		health.Details["reason"] = "node not found"
		return health, nil
	}

	if node.Status != pkg.NodeStatusOnline {
		health.Status = "unhealthy"
		health.Details["reason"] = "node offline"
		health.Details["node_status"] = string(node.Status)
		return health, nil
	}

	if service.Status != pkg.ServiceStatusActive {
		health.Status = "unhealthy"
		health.Details["reason"] = "service inactive"
		health.Details["service_status"] = string(service.Status)
		return health, nil
	}

	lastSeenThreshold := time.Now().Add(-5 * time.Minute)
	if service.LastSeen.Before(lastSeenThreshold) {
		health.Status = "degraded"
		health.Details["reason"] = "service not recently seen"
		health.Details["last_seen"] = service.LastSeen.Format(time.RFC3339)
	} else if node.LastSeen.Before(lastSeenThreshold) {
		health.Status = "degraded"
		health.Details["reason"] = "node not recently seen"
		health.Details["last_seen"] = node.LastSeen.Format(time.RFC3339)
	} else {
		health.Status = "healthy"
	}

	return health, nil
}
