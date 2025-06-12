package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	_ "github.com/lib/pq"
)

type PostgreSQLDB struct {
	db *sql.DB
}

func NewPostgreSQL(connection string) (*PostgreSQLDB, error) {
	db, err := sql.Open("postgres", connection)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	storage := &PostgreSQLDB{db: db}
	if err := storage.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return storage, nil
}

func (s *PostgreSQLDB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS nodes (
		id VARCHAR(36) PRIMARY KEY,
		name VARCHAR(255) UNIQUE NOT NULL,
		address VARCHAR(255) NOT NULL,
		port INTEGER NOT NULL,
		certificate TEXT,
		certificate_hash VARCHAR(255),
		metadata JSONB,
		status VARCHAR(50) NOT NULL DEFAULT 'online',
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		last_seen TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS services (
		id VARCHAR(36) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		node_id VARCHAR(36) NOT NULL,
		definition VARCHAR(255) NOT NULL,
		uri VARCHAR(500) NOT NULL,
		method VARCHAR(10) NOT NULL,
		metadata JSONB,
		version VARCHAR(50) NOT NULL DEFAULT '1.0',
		status VARCHAR(50) NOT NULL DEFAULT 'active',
		health_check VARCHAR(500),
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		last_seen TIMESTAMP NOT NULL,
		FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
		UNIQUE(node_id, uri, method)
	);

	CREATE TABLE IF NOT EXISTS auth_rules (
		id VARCHAR(36) PRIMARY KEY,
		consumer_id VARCHAR(36) NOT NULL,
		provider_id VARCHAR(36) NOT NULL,
		service_id VARCHAR(36) NOT NULL,
		created_at TIMESTAMP NOT NULL,
		FOREIGN KEY (consumer_id) REFERENCES nodes(id) ON DELETE CASCADE,
		FOREIGN KEY (provider_id) REFERENCES nodes(id) ON DELETE CASCADE,
		FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
		UNIQUE(consumer_id, provider_id, service_id)
	);

	CREATE TABLE IF NOT EXISTS events (
		id VARCHAR(36) PRIMARY KEY,
		type VARCHAR(100) NOT NULL,
		topic VARCHAR(255) NOT NULL,
		publisher_id VARCHAR(36) NOT NULL,
		payload BYTEA NOT NULL,
		metadata JSONB,
		created_at TIMESTAMP NOT NULL,
		FOREIGN KEY (publisher_id) REFERENCES nodes(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS subscriptions (
		id VARCHAR(36) PRIMARY KEY,
		subscriber_id VARCHAR(36) NOT NULL,
		topic VARCHAR(255) NOT NULL,
		endpoint VARCHAR(500) NOT NULL,
		filters JSONB,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		FOREIGN KEY (subscriber_id) REFERENCES nodes(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS gateways (
		id VARCHAR(36) PRIMARY KEY,
		name VARCHAR(255) UNIQUE NOT NULL,
		address VARCHAR(255) NOT NULL,
		port INTEGER NOT NULL,
		cloud_id VARCHAR(255) NOT NULL,
		certificate TEXT,
		certificate_hash VARCHAR(255),
		public_key TEXT,
		metadata JSONB,
		status VARCHAR(50) NOT NULL DEFAULT 'online',
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		last_seen TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS gateway_tunnels (
		id VARCHAR(36) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		local_gateway_id VARCHAR(36) NOT NULL,
		remote_gateway_id VARCHAR(36) NOT NULL,
		remote_address VARCHAR(255) NOT NULL,
		remote_port INTEGER NOT NULL,
		protocol VARCHAR(50) NOT NULL,
		encryption_type VARCHAR(100) NOT NULL,
		shared_secret TEXT,
		status VARCHAR(50) NOT NULL DEFAULT 'inactive',
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		last_used TIMESTAMP NOT NULL,
		FOREIGN KEY (local_gateway_id) REFERENCES gateways(id) ON DELETE CASCADE,
		FOREIGN KEY (remote_gateway_id) REFERENCES gateways(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS gateway_sessions (
		id VARCHAR(36) PRIMARY KEY,
		tunnel_id VARCHAR(36) NOT NULL,
		requester_id VARCHAR(36) NOT NULL,
		provider_id VARCHAR(36) NOT NULL,
		service_id VARCHAR(36) NOT NULL,
		session_token VARCHAR(255) UNIQUE NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		status VARCHAR(50) NOT NULL DEFAULT 'pending',
		metadata JSONB,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		last_activity_at TIMESTAMP NOT NULL,
		FOREIGN KEY (tunnel_id) REFERENCES gateway_tunnels(id) ON DELETE CASCADE,
		FOREIGN KEY (requester_id) REFERENCES nodes(id) ON DELETE CASCADE,
		FOREIGN KEY (provider_id) REFERENCES nodes(id) ON DELETE CASCADE,
		FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS relay_connections (
		id VARCHAR(36) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		gateway_id VARCHAR(36) NOT NULL,
		broker_type VARCHAR(50) NOT NULL,
		broker_url VARCHAR(500) NOT NULL,
		username VARCHAR(255),
		password VARCHAR(255),
		tls_enabled BOOLEAN NOT NULL DEFAULT false,
		cert_path VARCHAR(500),
		key_path VARCHAR(500),
		ca_cert_path VARCHAR(500),
		max_retries INTEGER NOT NULL DEFAULT 3,
		retry_delay BIGINT NOT NULL DEFAULT 5000000000,
		status VARCHAR(50) NOT NULL DEFAULT 'disconnected',
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		last_ping_at TIMESTAMP,
		error_message TEXT,
		FOREIGN KEY (gateway_id) REFERENCES gateways(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_services_name ON services(name);
	CREATE INDEX IF NOT EXISTS idx_services_node_id ON services(node_id);
	CREATE INDEX IF NOT EXISTS idx_auth_consumer ON auth_rules(consumer_id);
	CREATE INDEX IF NOT EXISTS idx_auth_provider ON auth_rules(provider_id);
	CREATE INDEX IF NOT EXISTS idx_events_topic ON events(topic);
	CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
	CREATE INDEX IF NOT EXISTS idx_subscriptions_topic ON subscriptions(topic);
	CREATE INDEX IF NOT EXISTS idx_gateways_cloud_id ON gateways(cloud_id);
	CREATE INDEX IF NOT EXISTS idx_tunnels_local_gateway ON gateway_tunnels(local_gateway_id);
	CREATE INDEX IF NOT EXISTS idx_tunnels_remote_gateway ON gateway_tunnels(remote_gateway_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_tunnel ON gateway_sessions(tunnel_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_token ON gateway_sessions(session_token);
	CREATE INDEX IF NOT EXISTS idx_relay_gateway ON relay_connections(gateway_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

func (s *PostgreSQLDB) CreateNode(node *pkg.Node) error {
	metadata, _ := json.Marshal(node.Metadata)

	query := `
		INSERT INTO nodes (id, name, address, port, certificate, certificate_hash, metadata, status, created_at, updated_at, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := s.db.Exec(query,
		node.ID, node.Name, node.Address, node.Port,
		node.Certificate, node.CertificateHash, string(metadata),
		node.Status, node.CreatedAt, node.UpdatedAt, node.LastSeen,
	)
	return err
}

func (s *PostgreSQLDB) GetNode(id string) (*pkg.Node, error) {
	query := `
		SELECT id, name, address, port, certificate, certificate_hash, metadata, status, created_at, updated_at, last_seen
		FROM nodes WHERE id = $1
	`

	var node pkg.Node
	var metadataStr string

	err := s.db.QueryRow(query, id).Scan(
		&node.ID, &node.Name, &node.Address, &node.Port,
		&node.Certificate, &node.CertificateHash, &metadataStr,
		&node.Status, &node.CreatedAt, &node.UpdatedAt, &node.LastSeen,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if metadataStr != "" {
		json.Unmarshal([]byte(metadataStr), &node.Metadata)
	}

	return &node, nil
}

func (s *PostgreSQLDB) GetNodeByName(name string) (*pkg.Node, error) {
	query := `
		SELECT id, name, address, port, certificate, certificate_hash, metadata, status, created_at, updated_at, last_seen
		FROM nodes WHERE name = $1
	`

	var node pkg.Node
	var metadataStr string

	err := s.db.QueryRow(query, name).Scan(
		&node.ID, &node.Name, &node.Address, &node.Port,
		&node.Certificate, &node.CertificateHash, &metadataStr,
		&node.Status, &node.CreatedAt, &node.UpdatedAt, &node.LastSeen,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if metadataStr != "" {
		json.Unmarshal([]byte(metadataStr), &node.Metadata)
	}

	return &node, nil
}

func (s *PostgreSQLDB) UpdateNode(node *pkg.Node) error {
	metadata, _ := json.Marshal(node.Metadata)

	query := `
		UPDATE nodes SET name = $1, address = $2, port = $3, certificate = $4, certificate_hash = $5, 
		metadata = $6, status = $7, updated_at = $8, last_seen = $9
		WHERE id = $10
	`

	_, err := s.db.Exec(query,
		node.Name, node.Address, node.Port, node.Certificate, node.CertificateHash,
		string(metadata), node.Status, node.UpdatedAt, node.LastSeen, node.ID,
	)
	return err
}

func (s *PostgreSQLDB) DeleteNode(id string) error {
	query := "DELETE FROM nodes WHERE id = $1"
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgreSQLDB) ListNodes() ([]*pkg.Node, error) {
	query := `
		SELECT id, name, address, port, certificate, certificate_hash, metadata, status, created_at, updated_at, last_seen
		FROM nodes ORDER BY name
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*pkg.Node
	for rows.Next() {
		var node pkg.Node
		var metadataStr string

		err := rows.Scan(
			&node.ID, &node.Name, &node.Address, &node.Port,
			&node.Certificate, &node.CertificateHash, &metadataStr,
			&node.Status, &node.CreatedAt, &node.UpdatedAt, &node.LastSeen,
		)
		if err != nil {
			return nil, err
		}

		if metadataStr != "" {
			json.Unmarshal([]byte(metadataStr), &node.Metadata)
		}

		nodes = append(nodes, &node)
	}

	return nodes, nil
}

func (s *PostgreSQLDB) CreateService(service *pkg.Service) error {
	metadata, _ := json.Marshal(service.Metadata)

	query := `
		INSERT INTO services (id, name, node_id, definition, uri, method, metadata, version, status, health_check, created_at, updated_at, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err := s.db.Exec(query,
		service.ID, service.Name, service.NodeID, service.Definition, service.URI, service.Method,
		string(metadata), service.Version, service.Status, service.HealthCheck,
		service.CreatedAt, service.UpdatedAt, service.LastSeen,
	)
	return err
}

func (s *PostgreSQLDB) GetService(id string) (*pkg.Service, error) {
	query := `
		SELECT id, name, node_id, definition, uri, method, metadata, version, status, health_check, created_at, updated_at, last_seen
		FROM services WHERE id = $1
	`

	var service pkg.Service
	var metadataStr string

	err := s.db.QueryRow(query, id).Scan(
		&service.ID, &service.Name, &service.NodeID, &service.Definition, &service.URI, &service.Method,
		&metadataStr, &service.Version, &service.Status, &service.HealthCheck,
		&service.CreatedAt, &service.UpdatedAt, &service.LastSeen,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if metadataStr != "" {
		json.Unmarshal([]byte(metadataStr), &service.Metadata)
	}

	return &service, nil
}

func (s *PostgreSQLDB) GetServicesByNode(nodeID string) ([]*pkg.Service, error) {
	query := `
		SELECT id, name, node_id, definition, uri, method, metadata, version, status, health_check, created_at, updated_at, last_seen
		FROM services WHERE node_id = $1 ORDER BY name
	`

	rows, err := s.db.Query(query, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []*pkg.Service
	for rows.Next() {
		var service pkg.Service
		var metadataStr string

		err := rows.Scan(
			&service.ID, &service.Name, &service.NodeID, &service.Definition, &service.URI, &service.Method,
			&metadataStr, &service.Version, &service.Status, &service.HealthCheck,
			&service.CreatedAt, &service.UpdatedAt, &service.LastSeen,
		)
		if err != nil {
			return nil, err
		}

		if metadataStr != "" {
			json.Unmarshal([]byte(metadataStr), &service.Metadata)
		}

		services = append(services, &service)
	}

	return services, nil
}

func (s *PostgreSQLDB) GetServicesByName(name string) ([]*pkg.Service, error) {
	query := `
		SELECT id, name, node_id, definition, uri, method, metadata, version, status, health_check, created_at, updated_at, last_seen
		FROM services WHERE name = $1 ORDER BY created_at DESC
	`

	rows, err := s.db.Query(query, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []*pkg.Service
	for rows.Next() {
		var service pkg.Service
		var metadataStr string

		err := rows.Scan(
			&service.ID, &service.Name, &service.NodeID, &service.Definition, &service.URI, &service.Method,
			&metadataStr, &service.Version, &service.Status, &service.HealthCheck,
			&service.CreatedAt, &service.UpdatedAt, &service.LastSeen,
		)
		if err != nil {
			return nil, err
		}

		if metadataStr != "" {
			json.Unmarshal([]byte(metadataStr), &service.Metadata)
		}

		services = append(services, &service)
	}

	return services, nil
}

func (s *PostgreSQLDB) UpdateService(service *pkg.Service) error {
	metadata, _ := json.Marshal(service.Metadata)

	query := `
		UPDATE services SET name = $1, definition = $2, uri = $3, method = $4, metadata = $5, 
		version = $6, status = $7, health_check = $8, updated_at = $9, last_seen = $10
		WHERE id = $11
	`

	_, err := s.db.Exec(query,
		service.Name, service.Definition, service.URI, service.Method, string(metadata),
		service.Version, service.Status, service.HealthCheck, service.UpdatedAt, service.LastSeen,
		service.ID,
	)
	return err
}

func (s *PostgreSQLDB) DeleteService(id string) error {
	query := "DELETE FROM services WHERE id = $1"
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgreSQLDB) ListServices() ([]*pkg.Service, error) {
	query := `
		SELECT id, name, node_id, definition, uri, method, metadata, version, status, health_check, created_at, updated_at, last_seen
		FROM services ORDER BY name
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []*pkg.Service
	for rows.Next() {
		var service pkg.Service
		var metadataStr string

		err := rows.Scan(
			&service.ID, &service.Name, &service.NodeID, &service.Definition, &service.URI, &service.Method,
			&metadataStr, &service.Version, &service.Status, &service.HealthCheck,
			&service.CreatedAt, &service.UpdatedAt, &service.LastSeen,
		)
		if err != nil {
			return nil, err
		}

		if metadataStr != "" {
			json.Unmarshal([]byte(metadataStr), &service.Metadata)
		}

		services = append(services, &service)
	}

	return services, nil
}

func (s *PostgreSQLDB) CreateAuthRule(rule *pkg.AuthRule) error {
	query := `
		INSERT INTO auth_rules (id, consumer_id, provider_id, service_id, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := s.db.Exec(query, rule.ID, rule.ConsumerID, rule.ProviderID, rule.ServiceID, rule.CreatedAt)
	return err
}

func (s *PostgreSQLDB) GetAuthRule(id string) (*pkg.AuthRule, error) {
	query := `
		SELECT id, consumer_id, provider_id, service_id, created_at
		FROM auth_rules WHERE id = $1
	`

	var rule pkg.AuthRule
	err := s.db.QueryRow(query, id).Scan(
		&rule.ID, &rule.ConsumerID, &rule.ProviderID, &rule.ServiceID, &rule.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &rule, nil
}

func (s *PostgreSQLDB) GetAuthRules(consumerID, providerID, serviceID string) ([]*pkg.AuthRule, error) {
	query := `
		SELECT id, consumer_id, provider_id, service_id, created_at
		FROM auth_rules WHERE consumer_id = $1 AND provider_id = $2 AND service_id = $3
	`

	rows, err := s.db.Query(query, consumerID, providerID, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*pkg.AuthRule
	for rows.Next() {
		var rule pkg.AuthRule
		err := rows.Scan(&rule.ID, &rule.ConsumerID, &rule.ProviderID, &rule.ServiceID, &rule.CreatedAt)
		if err != nil {
			return nil, err
		}
		rules = append(rules, &rule)
	}

	return rules, nil
}

func (s *PostgreSQLDB) DeleteAuthRule(id string) error {
	query := "DELETE FROM auth_rules WHERE id = $1"
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgreSQLDB) ListAuthRules() ([]*pkg.AuthRule, error) {
	query := `
		SELECT id, consumer_id, provider_id, service_id, created_at
		FROM auth_rules ORDER BY created_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*pkg.AuthRule
	for rows.Next() {
		var rule pkg.AuthRule
		err := rows.Scan(&rule.ID, &rule.ConsumerID, &rule.ProviderID, &rule.ServiceID, &rule.CreatedAt)
		if err != nil {
			return nil, err
		}
		rules = append(rules, &rule)
	}

	return rules, nil
}

func (s *PostgreSQLDB) CreateEvent(event *pkg.Event) error {
	metadata, _ := json.Marshal(event.Metadata)

	query := `
		INSERT INTO events (id, type, topic, publisher_id, payload, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := s.db.Exec(query,
		event.ID, event.Type, event.Topic, event.PublisherID, event.Payload, string(metadata), event.CreatedAt,
	)
	return err
}

func (s *PostgreSQLDB) GetEvent(id string) (*pkg.Event, error) {
	query := `
		SELECT id, type, topic, publisher_id, payload, metadata, created_at
		FROM events WHERE id = $1
	`

	var event pkg.Event
	var metadataStr string

	err := s.db.QueryRow(query, id).Scan(
		&event.ID, &event.Type, &event.Topic, &event.PublisherID, &event.Payload, &metadataStr, &event.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if metadataStr != "" {
		json.Unmarshal([]byte(metadataStr), &event.Metadata)
	}

	return &event, nil
}

func (s *PostgreSQLDB) ListEvents(limit int) ([]*pkg.Event, error) {
	query := `
		SELECT id, type, topic, publisher_id, payload, metadata, created_at
		FROM events ORDER BY created_at DESC LIMIT $1
	`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*pkg.Event
	for rows.Next() {
		var event pkg.Event
		var metadataStr string

		err := rows.Scan(
			&event.ID, &event.Type, &event.Topic, &event.PublisherID, &event.Payload, &metadataStr, &event.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if metadataStr != "" {
			json.Unmarshal([]byte(metadataStr), &event.Metadata)
		}

		events = append(events, &event)
	}

	return events, nil
}

func (s *PostgreSQLDB) DeleteOldEvents(before time.Time) error {
	query := "DELETE FROM events WHERE created_at < $1"
	_, err := s.db.Exec(query, before)
	return err
}

func (s *PostgreSQLDB) CreateSubscription(sub *pkg.Subscription) error {
	filters, _ := json.Marshal(sub.Filters)

	query := `
		INSERT INTO subscriptions (id, subscriber_id, topic, endpoint, filters, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := s.db.Exec(query,
		sub.ID, sub.SubscriberID, sub.Topic, sub.Endpoint, string(filters), sub.CreatedAt, sub.UpdatedAt,
	)
	return err
}

func (s *PostgreSQLDB) GetSubscription(id string) (*pkg.Subscription, error) {
	query := `
		SELECT id, subscriber_id, topic, endpoint, filters, created_at, updated_at
		FROM subscriptions WHERE id = $1
	`

	var sub pkg.Subscription
	var filtersStr string

	err := s.db.QueryRow(query, id).Scan(
		&sub.ID, &sub.SubscriberID, &sub.Topic, &sub.Endpoint, &filtersStr, &sub.CreatedAt, &sub.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if filtersStr != "" {
		json.Unmarshal([]byte(filtersStr), &sub.Filters)
	}

	return &sub, nil
}

func (s *PostgreSQLDB) GetSubscriptionsByTopic(topic string) ([]*pkg.Subscription, error) {
	query := `
		SELECT id, subscriber_id, topic, endpoint, filters, created_at, updated_at
		FROM subscriptions WHERE topic = $1 ORDER BY created_at
	`

	rows, err := s.db.Query(query, topic)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subscriptions []*pkg.Subscription
	for rows.Next() {
		var sub pkg.Subscription
		var filtersStr string

		err := rows.Scan(
			&sub.ID, &sub.SubscriberID, &sub.Topic, &sub.Endpoint, &filtersStr, &sub.CreatedAt, &sub.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if filtersStr != "" {
			json.Unmarshal([]byte(filtersStr), &sub.Filters)
		}

		subscriptions = append(subscriptions, &sub)
	}

	return subscriptions, nil
}

func (s *PostgreSQLDB) UpdateSubscription(sub *pkg.Subscription) error {
	filters, _ := json.Marshal(sub.Filters)

	query := `
		UPDATE subscriptions SET topic = $1, endpoint = $2, filters = $3, updated_at = $4
		WHERE id = $5
	`

	_, err := s.db.Exec(query, sub.Topic, sub.Endpoint, string(filters), sub.UpdatedAt, sub.ID)
	return err
}

func (s *PostgreSQLDB) DeleteSubscription(id string) error {
	query := "DELETE FROM subscriptions WHERE id = $1"
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgreSQLDB) ListSubscriptions() ([]*pkg.Subscription, error) {
	query := `
		SELECT id, subscriber_id, topic, endpoint, filters, created_at, updated_at
		FROM subscriptions ORDER BY topic, created_at
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subscriptions []*pkg.Subscription
	for rows.Next() {
		var sub pkg.Subscription
		var filtersStr string

		err := rows.Scan(
			&sub.ID, &sub.SubscriberID, &sub.Topic, &sub.Endpoint, &filtersStr, &sub.CreatedAt, &sub.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if filtersStr != "" {
			json.Unmarshal([]byte(filtersStr), &sub.Filters)
		}

		subscriptions = append(subscriptions, &sub)
	}

	return subscriptions, nil
}

func (s *PostgreSQLDB) CreateGateway(gateway *pkg.Gateway) error {
	metadata, _ := json.Marshal(gateway.Metadata)

	query := `
		INSERT INTO gateways (id, name, address, port, cloud_id, certificate, certificate_hash, public_key, metadata, status, created_at, updated_at, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err := s.db.Exec(query,
		gateway.ID, gateway.Name, gateway.Address, gateway.Port, gateway.CloudID,
		gateway.Certificate, gateway.CertificateHash, gateway.PublicKey, string(metadata),
		gateway.Status, gateway.CreatedAt, gateway.UpdatedAt, gateway.LastSeen,
	)
	return err
}

func (s *PostgreSQLDB) GetGateway(id string) (*pkg.Gateway, error) {
	query := `
		SELECT id, name, address, port, cloud_id, certificate, certificate_hash, public_key, metadata, status, created_at, updated_at, last_seen
		FROM gateways WHERE id = $1
	`

	var gateway pkg.Gateway
	var metadataStr string

	err := s.db.QueryRow(query, id).Scan(
		&gateway.ID, &gateway.Name, &gateway.Address, &gateway.Port, &gateway.CloudID,
		&gateway.Certificate, &gateway.CertificateHash, &gateway.PublicKey, &metadataStr,
		&gateway.Status, &gateway.CreatedAt, &gateway.UpdatedAt, &gateway.LastSeen,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if metadataStr != "" {
		json.Unmarshal([]byte(metadataStr), &gateway.Metadata)
	}

	return &gateway, nil
}

func (s *PostgreSQLDB) UpdateGateway(gateway *pkg.Gateway) error {
	metadata, _ := json.Marshal(gateway.Metadata)

	query := `
		UPDATE gateways SET name = $1, address = $2, port = $3, cloud_id = $4, certificate = $5, 
		certificate_hash = $6, public_key = $7, metadata = $8, status = $9, updated_at = $10, last_seen = $11
		WHERE id = $12
	`

	_, err := s.db.Exec(query,
		gateway.Name, gateway.Address, gateway.Port, gateway.CloudID, gateway.Certificate,
		gateway.CertificateHash, gateway.PublicKey, string(metadata), gateway.Status,
		gateway.UpdatedAt, gateway.LastSeen, gateway.ID,
	)
	return err
}

func (s *PostgreSQLDB) DeleteGateway(id string) error {
	query := "DELETE FROM gateways WHERE id = $1"
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgreSQLDB) ListGateways() ([]*pkg.Gateway, error) {
	query := `
		SELECT id, name, address, port, cloud_id, certificate, certificate_hash, public_key, metadata, status, created_at, updated_at, last_seen
		FROM gateways ORDER BY name
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var gateways []*pkg.Gateway
	for rows.Next() {
		var gateway pkg.Gateway
		var metadataStr string

		err := rows.Scan(
			&gateway.ID, &gateway.Name, &gateway.Address, &gateway.Port, &gateway.CloudID,
			&gateway.Certificate, &gateway.CertificateHash, &gateway.PublicKey, &metadataStr,
			&gateway.Status, &gateway.CreatedAt, &gateway.UpdatedAt, &gateway.LastSeen,
		)
		if err != nil {
			return nil, err
		}

		if metadataStr != "" {
			json.Unmarshal([]byte(metadataStr), &gateway.Metadata)
		}

		gateways = append(gateways, &gateway)
	}

	return gateways, nil
}

func (s *PostgreSQLDB) CreateTunnel(tunnel *pkg.GatewayTunnel) error {
	query := `
		INSERT INTO gateway_tunnels (id, name, local_gateway_id, remote_gateway_id, remote_address, remote_port, protocol, encryption_type, shared_secret, status, created_at, updated_at, last_used)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err := s.db.Exec(query,
		tunnel.ID, tunnel.Name, tunnel.LocalGatewayID, tunnel.RemoteGatewayID,
		tunnel.RemoteAddress, tunnel.RemotePort, tunnel.Protocol, tunnel.EncryptionType,
		tunnel.SharedSecret, tunnel.Status, tunnel.CreatedAt, tunnel.UpdatedAt, tunnel.LastUsed,
	)
	return err
}

func (s *PostgreSQLDB) GetTunnel(id string) (*pkg.GatewayTunnel, error) {
	query := `
		SELECT id, name, local_gateway_id, remote_gateway_id, remote_address, remote_port, protocol, encryption_type, shared_secret, status, created_at, updated_at, last_used
		FROM gateway_tunnels WHERE id = $1
	`

	var tunnel pkg.GatewayTunnel

	err := s.db.QueryRow(query, id).Scan(
		&tunnel.ID, &tunnel.Name, &tunnel.LocalGatewayID, &tunnel.RemoteGatewayID,
		&tunnel.RemoteAddress, &tunnel.RemotePort, &tunnel.Protocol, &tunnel.EncryptionType,
		&tunnel.SharedSecret, &tunnel.Status, &tunnel.CreatedAt, &tunnel.UpdatedAt, &tunnel.LastUsed,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &tunnel, nil
}

func (s *PostgreSQLDB) UpdateTunnel(tunnel *pkg.GatewayTunnel) error {
	query := `
		UPDATE gateway_tunnels SET name = $1, remote_address = $2, remote_port = $3, protocol = $4, 
		encryption_type = $5, shared_secret = $6, status = $7, updated_at = $8, last_used = $9
		WHERE id = $10
	`

	_, err := s.db.Exec(query,
		tunnel.Name, tunnel.RemoteAddress, tunnel.RemotePort, tunnel.Protocol,
		tunnel.EncryptionType, tunnel.SharedSecret, tunnel.Status, tunnel.UpdatedAt, tunnel.LastUsed,
		tunnel.ID,
	)
	return err
}

func (s *PostgreSQLDB) DeleteTunnel(id string) error {
	query := "DELETE FROM gateway_tunnels WHERE id = $1"
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgreSQLDB) ListTunnelsByGateway(gatewayID string) ([]*pkg.GatewayTunnel, error) {
	query := `
		SELECT id, name, local_gateway_id, remote_gateway_id, remote_address, remote_port, protocol, encryption_type, shared_secret, status, created_at, updated_at, last_used
		FROM gateway_tunnels WHERE local_gateway_id = $1 ORDER BY name
	`

	rows, err := s.db.Query(query, gatewayID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tunnels []*pkg.GatewayTunnel
	for rows.Next() {
		var tunnel pkg.GatewayTunnel

		err := rows.Scan(
			&tunnel.ID, &tunnel.Name, &tunnel.LocalGatewayID, &tunnel.RemoteGatewayID,
			&tunnel.RemoteAddress, &tunnel.RemotePort, &tunnel.Protocol, &tunnel.EncryptionType,
			&tunnel.SharedSecret, &tunnel.Status, &tunnel.CreatedAt, &tunnel.UpdatedAt, &tunnel.LastUsed,
		)
		if err != nil {
			return nil, err
		}

		tunnels = append(tunnels, &tunnel)
	}

	return tunnels, nil
}

func (s *PostgreSQLDB) CreateSession(session *pkg.GatewaySession) error {
	metadata, _ := json.Marshal(session.Metadata)

	query := `
		INSERT INTO gateway_sessions (id, tunnel_id, requester_id, provider_id, service_id, session_token, expires_at, status, metadata, created_at, updated_at, last_activity_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := s.db.Exec(query,
		session.ID, session.TunnelID, session.RequesterID, session.ProviderID, session.ServiceID,
		session.SessionToken, session.ExpiresAt, session.Status, string(metadata),
		session.CreatedAt, session.UpdatedAt, session.LastActivityAt,
	)
	return err
}

func (s *PostgreSQLDB) GetSession(id string) (*pkg.GatewaySession, error) {
	query := `
		SELECT id, tunnel_id, requester_id, provider_id, service_id, session_token, expires_at, status, metadata, created_at, updated_at, last_activity_at
		FROM gateway_sessions WHERE id = $1
	`

	var session pkg.GatewaySession
	var metadataStr string

	err := s.db.QueryRow(query, id).Scan(
		&session.ID, &session.TunnelID, &session.RequesterID, &session.ProviderID, &session.ServiceID,
		&session.SessionToken, &session.ExpiresAt, &session.Status, &metadataStr,
		&session.CreatedAt, &session.UpdatedAt, &session.LastActivityAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if metadataStr != "" {
		json.Unmarshal([]byte(metadataStr), &session.Metadata)
	}

	return &session, nil
}

func (s *PostgreSQLDB) UpdateSession(session *pkg.GatewaySession) error {
	metadata, _ := json.Marshal(session.Metadata)

	query := `
		UPDATE gateway_sessions SET expires_at = $1, status = $2, metadata = $3, updated_at = $4, last_activity_at = $5
		WHERE id = $6
	`

	_, err := s.db.Exec(query,
		session.ExpiresAt, session.Status, string(metadata), session.UpdatedAt, session.LastActivityAt,
		session.ID,
	)
	return err
}

func (s *PostgreSQLDB) DeleteSession(id string) error {
	query := "DELETE FROM gateway_sessions WHERE id = $1"
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgreSQLDB) ListSessionsByTunnel(tunnelID string) ([]*pkg.GatewaySession, error) {
	query := `
		SELECT id, tunnel_id, requester_id, provider_id, service_id, session_token, expires_at, status, metadata, created_at, updated_at, last_activity_at
		FROM gateway_sessions WHERE tunnel_id = $1 ORDER BY created_at DESC
	`

	rows, err := s.db.Query(query, tunnelID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*pkg.GatewaySession
	for rows.Next() {
		var session pkg.GatewaySession
		var metadataStr string

		err := rows.Scan(
			&session.ID, &session.TunnelID, &session.RequesterID, &session.ProviderID, &session.ServiceID,
			&session.SessionToken, &session.ExpiresAt, &session.Status, &metadataStr,
			&session.CreatedAt, &session.UpdatedAt, &session.LastActivityAt,
		)
		if err != nil {
			return nil, err
		}

		if metadataStr != "" {
			json.Unmarshal([]byte(metadataStr), &session.Metadata)
		}

		sessions = append(sessions, &session)
	}

	return sessions, nil
}

func (s *PostgreSQLDB) CreateRelayConnection(connection *pkg.RelayConnection) error {
	query := `
		INSERT INTO relay_connections (id, name, gateway_id, broker_type, broker_url, username, password, tls_enabled, cert_path, key_path, ca_cert_path, max_retries, retry_delay, status, created_at, updated_at, last_ping_at, error_message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`

	_, err := s.db.Exec(query,
		connection.ID, connection.Name, connection.GatewayID, connection.BrokerType, connection.BrokerURL,
		connection.Username, connection.Password, connection.TLSEnabled, connection.CertPath, connection.KeyPath,
		connection.CACertPath, connection.MaxRetries, connection.RetryDelay, connection.Status,
		connection.CreatedAt, connection.UpdatedAt, connection.LastPingAt, connection.ErrorMessage,
	)
	return err
}

func (s *PostgreSQLDB) GetRelayConnection(id string) (*pkg.RelayConnection, error) {
	query := `
		SELECT id, name, gateway_id, broker_type, broker_url, username, password, tls_enabled, cert_path, key_path, ca_cert_path, max_retries, retry_delay, status, created_at, updated_at, last_ping_at, error_message
		FROM relay_connections WHERE id = $1
	`

	var connection pkg.RelayConnection

	err := s.db.QueryRow(query, id).Scan(
		&connection.ID, &connection.Name, &connection.GatewayID, &connection.BrokerType, &connection.BrokerURL,
		&connection.Username, &connection.Password, &connection.TLSEnabled, &connection.CertPath, &connection.KeyPath,
		&connection.CACertPath, &connection.MaxRetries, &connection.RetryDelay, &connection.Status,
		&connection.CreatedAt, &connection.UpdatedAt, &connection.LastPingAt, &connection.ErrorMessage,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &connection, nil
}

func (s *PostgreSQLDB) UpdateRelayConnection(connection *pkg.RelayConnection) error {
	query := `
		UPDATE relay_connections SET name = $1, broker_url = $2, username = $3, password = $4, tls_enabled = $5, 
		cert_path = $6, key_path = $7, ca_cert_path = $8, max_retries = $9, retry_delay = $10, status = $11, 
		updated_at = $12, last_ping_at = $13, error_message = $14
		WHERE id = $15
	`

	_, err := s.db.Exec(query,
		connection.Name, connection.BrokerURL, connection.Username, connection.Password, connection.TLSEnabled,
		connection.CertPath, connection.KeyPath, connection.CACertPath, connection.MaxRetries, connection.RetryDelay,
		connection.Status, connection.UpdatedAt, connection.LastPingAt, connection.ErrorMessage,
		connection.ID,
	)
	return err
}

func (s *PostgreSQLDB) DeleteRelayConnection(id string) error {
	query := "DELETE FROM relay_connections WHERE id = $1"
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgreSQLDB) ListRelayConnectionsByGateway(gatewayID string) ([]*pkg.RelayConnection, error) {
	query := `
		SELECT id, name, gateway_id, broker_type, broker_url, username, password, tls_enabled, cert_path, key_path, ca_cert_path, max_retries, retry_delay, status, created_at, updated_at, last_ping_at, error_message
		FROM relay_connections WHERE gateway_id = $1 ORDER BY name
	`

	rows, err := s.db.Query(query, gatewayID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var connections []*pkg.RelayConnection
	for rows.Next() {
		var connection pkg.RelayConnection

		err := rows.Scan(
			&connection.ID, &connection.Name, &connection.GatewayID, &connection.BrokerType, &connection.BrokerURL,
			&connection.Username, &connection.Password, &connection.TLSEnabled, &connection.CertPath, &connection.KeyPath,
			&connection.CACertPath, &connection.MaxRetries, &connection.RetryDelay, &connection.Status,
			&connection.CreatedAt, &connection.UpdatedAt, &connection.LastPingAt, &connection.ErrorMessage,
		)
		if err != nil {
			return nil, err
		}

		connections = append(connections, &connection)
	}

	return connections, nil
}

func (s *PostgreSQLDB) GetMetrics() (*pkg.Metrics, error) {
	metrics := &pkg.Metrics{}

	queries := map[string]*int64{
		"SELECT COUNT(*) FROM nodes":                            &metrics.TotalNodes,
		"SELECT COUNT(*) FROM services":                         &metrics.TotalServices,
		"SELECT COUNT(*) FROM nodes WHERE status = 'online'":    &metrics.ActiveNodes,
		"SELECT COUNT(*) FROM services WHERE status = 'active'": &metrics.ActiveServices,
		"SELECT COUNT(*) FROM events":                           &metrics.TotalEvents,
		"SELECT COUNT(*) FROM subscriptions":                    &metrics.TotalSubscriptions,
	}

	for query, target := range queries {
		err := s.db.QueryRow(query).Scan(target)
		if err != nil {
			return nil, err
		}
	}

	return metrics, nil
}

func (s *PostgreSQLDB) Close() error {
	return s.db.Close()
}
