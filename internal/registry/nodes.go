package registry

import (
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RegisterNode registers a new node in the registry
func (r *Registry) RegisterNode(req *pkg.RegistrationRequest) (*pkg.Node, error) {
	node := &req.Node

	if node.ID == "" {
		node.ID = uuid.New().String()
	}

	now := time.Now()
	node.CreatedAt = now
	node.UpdatedAt = now
	node.LastSeen = now
	node.Status = pkg.NodeStatusOnline

	if node.Metadata == nil {
		node.Metadata = make(map[string]string)
	}

	existing, err := r.db.GetNodeByName(node.Name)
	if err != nil {
		r.logger.WithError(err).Error("Failed to check existing node")
		return nil, pkg.DatabaseError(err)
	}

	if existing != nil {
		return nil, pkg.ConflictError("Node with this name already exists")
	}

	if err := r.db.CreateNode(node); err != nil {
		r.logger.WithError(err).Error("Failed to create node")
		return nil, pkg.DatabaseError(err)
	}

	r.logger.WithFields(logrus.Fields{
		"node_id":   node.ID,
		"node_name": node.Name,
		"address":   node.Address,
		"port":      node.Port,
	}).Info("Node registered successfully")

	return node, nil
}

// UnregisterNode removes a node from the registry
func (r *Registry) UnregisterNode(nodeID string) error {
	existing, err := r.db.GetNode(nodeID)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get node")
		return pkg.DatabaseError(err)
	}

	if existing == nil {
		return pkg.NotFoundError("Node not found")
	}

	if err := r.db.DeleteNode(nodeID); err != nil {
		r.logger.WithError(err).Error("Failed to delete node")
		return pkg.DatabaseError(err)
	}

	r.logger.WithFields(logrus.Fields{
		"node_id":   nodeID,
		"node_name": existing.Name,
	}).Info("Node unregistered successfully")

	return nil
}

// GetNode retrieves a node by ID
func (r *Registry) GetNode(nodeID string) (*pkg.Node, error) {
	node, err := r.db.GetNode(nodeID)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get node")
		return nil, pkg.DatabaseError(err)
	}

	if node == nil {
		return nil, pkg.NotFoundError("Node not found")
	}

	return node, nil
}

// GetNodeByName retrieves a node by name
func (r *Registry) GetNodeByName(name string) (*pkg.Node, error) {
	node, err := r.db.GetNodeByName(name)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get node by name")
		return nil, pkg.DatabaseError(err)
	}

	if node == nil {
		return nil, pkg.NotFoundError("Node not found")
	}

	return node, nil
}

// ListNodes returns all registered nodes
func (r *Registry) ListNodes() ([]*pkg.Node, error) {
	nodes, err := r.db.ListNodes()
	if err != nil {
		r.logger.WithError(err).Error("Failed to list nodes")
		return nil, pkg.DatabaseError(err)
	}

	return nodes, nil
}

// UpdateNodeHeartbeat updates the last seen timestamp for a node
func (r *Registry) UpdateNodeHeartbeat(nodeID string) error {
	node, err := r.db.GetNode(nodeID)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get node for heartbeat")
		return pkg.DatabaseError(err)
	}

	if node == nil {
		return pkg.NotFoundError("Node not found")
	}

	node.LastSeen = time.Now()
	node.Status = pkg.NodeStatusOnline

	if err := r.db.UpdateNode(node); err != nil {
		r.logger.WithError(err).Error("Failed to update node heartbeat")
		return pkg.DatabaseError(err)
	}

	return nil
}

// CleanupInactiveNodes marks nodes as offline if they haven't been seen recently
func (r *Registry) CleanupInactiveNodes(inactiveThreshold time.Duration) error {
	nodes, err := r.db.ListNodes()
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-inactiveThreshold)
	var inactiveCount int

	for _, node := range nodes {
		if node.LastSeen.Before(cutoff) && node.Status == pkg.NodeStatusOnline {
			node.Status = pkg.NodeStatusOffline
			if err := r.db.UpdateNode(node); err != nil {
				r.logger.WithError(err).WithField("node_id", node.ID).Error("Failed to mark node as offline")
				continue
			}
			inactiveCount++
		}
	}

	if inactiveCount > 0 {
		r.logger.WithField("count", inactiveCount).Info("Marked inactive nodes as offline")
	}

	return nil
}
