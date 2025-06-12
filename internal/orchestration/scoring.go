package orchestration

import (
	"math"
	"sort"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
)

type ServiceCandidate struct {
	Service     *pkg.Service
	Node        *pkg.Node
	Score       float64
	Distance    float64
	Reliability float64
}

// calculateDistance computes the distance metric between requester and provider nodes
func (o *Orchestrator) calculateDistance(requester, provider *pkg.Node) float64 {
	if requester.Address == provider.Address {
		return 0.0
	}

	return 1.0
}

// calculateReliability computes the reliability metric for a service/node pair
func (o *Orchestrator) calculateReliability(service *pkg.Service, node *pkg.Node) float64 {
	reliability := 1.0

	lastSeenThreshold := time.Now().Add(-5 * time.Minute)
	if node.LastSeen.Before(lastSeenThreshold) {
		reliability *= 0.8
	}

	if service.LastSeen.Before(lastSeenThreshold) {
		reliability *= 0.8
	}

	if service.Status == pkg.ServiceStatusUnhealthy {
		reliability *= 0.5
	}

	return reliability
}

// calculateScore computes the overall score for a service candidate
func (o *Orchestrator) calculateScore(candidate *ServiceCandidate, preferences map[string]interface{}) float64 {
	score := 100.0

	distanceWeight := 0.3
	reliabilityWeight := 0.7

	if preferences != nil {
		if dw, ok := preferences["distance_weight"].(float64); ok {
			distanceWeight = dw
		}
		if rw, ok := preferences["reliability_weight"].(float64); ok {
			reliabilityWeight = rw
		}
	}

	score *= (1.0 - candidate.Distance*distanceWeight)
	score *= candidate.Reliability * reliabilityWeight

	if preferences != nil {
		if preferredVersion, ok := preferences["preferred_version"].(string); ok {
			if candidate.Service.Version == preferredVersion {
				score *= 1.2
			}
		}

		if preferredProvider, ok := preferences["preferred_provider"].(string); ok {
			if candidate.Node.Name == preferredProvider {
				score *= 1.5
			}
		}
	}

	return math.Max(0, score)
}

// rankCandidates sorts service candidates by score and applies result limits
func (o *Orchestrator) rankCandidates(candidates []*ServiceCandidate, preferences map[string]interface{}) []*ServiceCandidate {
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Score > candidates[j].Score
	})

	maxResults := 10
	if preferences != nil {
		if mr, ok := preferences["max_results"].(float64); ok {
			maxResults = int(mr)
		}
	}

	if len(candidates) > maxResults {
		candidates = candidates[:maxResults]
	}

	return candidates
}
