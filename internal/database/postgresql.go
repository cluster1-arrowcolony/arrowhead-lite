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
	-- Arrowhead 4.x Systems table
	CREATE TABLE IF NOT EXISTS systems (
		id SERIAL PRIMARY KEY,
		system_name VARCHAR(255) UNIQUE NOT NULL,
		address VARCHAR(255) NOT NULL,
		port INTEGER NOT NULL,
		authentication_info TEXT,
		metadata JSONB,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		UNIQUE(system_name, address, port)
	);

	-- Service Definitions table
	CREATE TABLE IF NOT EXISTS service_definitions (
		id SERIAL PRIMARY KEY,
		service_definition VARCHAR(255) UNIQUE NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);

	-- Interfaces table
	CREATE TABLE IF NOT EXISTS interfaces (
		id SERIAL PRIMARY KEY,
		interface_name VARCHAR(255) UNIQUE NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);

	-- Services table (Arrowhead 4.x)
	CREATE TABLE IF NOT EXISTS services (
		id SERIAL PRIMARY KEY,
		service_definition_id INTEGER NOT NULL,
		provider_id INTEGER NOT NULL,
		service_uri VARCHAR(500) NOT NULL,
		end_of_validity TIMESTAMP,
		secure VARCHAR(50) NOT NULL DEFAULT 'TOKEN',
		metadata JSONB,
		version INTEGER NOT NULL DEFAULT 1,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		FOREIGN KEY (service_definition_id) REFERENCES service_definitions (id) ON DELETE CASCADE,
		FOREIGN KEY (provider_id) REFERENCES systems (id) ON DELETE CASCADE,
		UNIQUE(service_definition_id, provider_id, service_uri)
	);

	-- Service-Interface many-to-many relationship
	CREATE TABLE IF NOT EXISTS service_interfaces (
		service_id INTEGER NOT NULL,
		interface_id INTEGER NOT NULL,
		PRIMARY KEY (service_id, interface_id),
		FOREIGN KEY (service_id) REFERENCES services (id) ON DELETE CASCADE,
		FOREIGN KEY (interface_id) REFERENCES interfaces (id) ON DELETE CASCADE
	);

	-- Authorizations table (Arrowhead 4.x)
	CREATE TABLE IF NOT EXISTS authorizations (
		id SERIAL PRIMARY KEY,
		consumer_id INTEGER NOT NULL,
		provider_id INTEGER NOT NULL,
		service_definition_id INTEGER NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		FOREIGN KEY (consumer_id) REFERENCES systems (id) ON DELETE CASCADE,
		FOREIGN KEY (provider_id) REFERENCES systems (id) ON DELETE CASCADE,
		FOREIGN KEY (service_definition_id) REFERENCES service_definitions (id) ON DELETE CASCADE,
		UNIQUE(consumer_id, provider_id, service_definition_id)
	);

	-- Authorization-Interface many-to-many relationship
	CREATE TABLE IF NOT EXISTS authorization_interfaces (
		authorization_id INTEGER NOT NULL,
		interface_id INTEGER NOT NULL,
		PRIMARY KEY (authorization_id, interface_id),
		FOREIGN KEY (authorization_id) REFERENCES authorizations (id) ON DELETE CASCADE,
		FOREIGN KEY (interface_id) REFERENCES interfaces (id) ON DELETE CASCADE
	);


	CREATE INDEX IF NOT EXISTS idx_systems_name ON systems(system_name);
	CREATE INDEX IF NOT EXISTS idx_systems_address_port ON systems(address, port);
	CREATE INDEX IF NOT EXISTS idx_services_definition ON services(service_definition_id);
	CREATE INDEX IF NOT EXISTS idx_services_provider ON services(provider_id);
	CREATE INDEX IF NOT EXISTS idx_authorizations_consumer ON authorizations(consumer_id);
	CREATE INDEX IF NOT EXISTS idx_authorizations_provider ON authorizations(provider_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// System operations

func (s *PostgreSQLDB) CreateSystem(system *pkg.System) error {
	metadataJSON := "{}"
	if system.Metadata != nil {
		if data, err := json.Marshal(system.Metadata); err == nil {
			metadataJSON = string(data)
		}
	}

	query := `INSERT INTO systems (system_name, address, port, authentication_info, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	err := s.db.QueryRow(query, system.SystemName, system.Address, system.Port,
		system.AuthenticationInfo, metadataJSON, system.CreatedAt, system.UpdatedAt).Scan(&system.ID)

	return err
}

func (s *PostgreSQLDB) GetSystemByID(id int) (*pkg.System, error) {
	query := `SELECT id, system_name, address, port, authentication_info, metadata, created_at, updated_at
		FROM systems WHERE id = $1`

	row := s.db.QueryRow(query, id)
	return s.scanSystem(row)
}

func (s *PostgreSQLDB) GetSystemByName(systemName string) (*pkg.System, error) {
	query := `SELECT id, system_name, address, port, authentication_info, metadata, created_at, updated_at
		FROM systems WHERE system_name = $1`

	row := s.db.QueryRow(query, systemName)
	return s.scanSystem(row)
}

func (s *PostgreSQLDB) GetSystemByParams(systemName, address string, port int) (*pkg.System, error) {
	query := `SELECT id, system_name, address, port, authentication_info, metadata, created_at, updated_at
		FROM systems WHERE system_name = $1 AND address = $2 AND port = $3`

	row := s.db.QueryRow(query, systemName, address, port)
	return s.scanSystem(row)
}

func (s *PostgreSQLDB) UpdateSystem(system *pkg.System) error {
	metadataJSON := "{}"
	if system.Metadata != nil {
		if data, err := json.Marshal(system.Metadata); err == nil {
			metadataJSON = string(data)
		}
	}

	query := `UPDATE systems SET system_name = $1, address = $2, port = $3, authentication_info = $4,
		metadata = $5, updated_at = $6 WHERE id = $7`

	_, err := s.db.Exec(query, system.SystemName, system.Address, system.Port,
		system.AuthenticationInfo, metadataJSON, system.UpdatedAt, system.ID)
	return err
}

func (s *PostgreSQLDB) DeleteSystemByID(id int) error {
	query := `DELETE FROM systems WHERE id = $1`
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgreSQLDB) DeleteSystemByParams(systemName, address string, port int) error {
	query := `DELETE FROM systems WHERE system_name = $1 AND address = $2 AND port = $3`
	_, err := s.db.Exec(query, systemName, address, port)
	return err
}

func (s *PostgreSQLDB) ListSystems(sortField, direction string) ([]pkg.System, error) {
	// Whitelist allowed sort fields to prevent SQL injection
	safeSortFields := map[string]string{
		"id":          "id",
		"system_name": "system_name",
		"address":     "address",
		"port":        "port",
		"createdAt":   "created_at",
		"updatedAt":   "updated_at",
	}

	// Get safe sort field or default
	orderBy, ok := safeSortFields[sortField]
	if !ok {
		orderBy = "id" // Default sort
	}

	// Validate direction
	if direction != "ASC" && direction != "DESC" {
		direction = "ASC" // Default direction
	}

	query := fmt.Sprintf(`SELECT id, system_name, address, port, authentication_info, metadata, created_at, updated_at
		FROM systems ORDER BY %s %s`, orderBy, direction)

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var systems []pkg.System
	for rows.Next() {
		system, err := s.scanSystemFromRows(rows)
		if err != nil {
			return nil, err
		}
		systems = append(systems, *system)
	}

	return systems, nil
}

func (s *PostgreSQLDB) scanSystem(row *sql.Row) (*pkg.System, error) {
	var system pkg.System
	var metadataJSON string
	var createdAt, updatedAt time.Time

	err := row.Scan(&system.ID, &system.SystemName, &system.Address, &system.Port,
		&system.AuthenticationInfo, &metadataJSON, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	system.CreatedAt = &createdAt
	system.UpdatedAt = &updatedAt

	if metadataJSON != "" && metadataJSON != "{}" {
		json.Unmarshal([]byte(metadataJSON), &system.Metadata)
	}

	return &system, nil
}

func (s *PostgreSQLDB) scanSystemFromRows(rows *sql.Rows) (*pkg.System, error) {
	var system pkg.System
	var metadataJSON string
	var createdAt, updatedAt time.Time

	err := rows.Scan(&system.ID, &system.SystemName, &system.Address, &system.Port,
		&system.AuthenticationInfo, &metadataJSON, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}

	system.CreatedAt = &createdAt
	system.UpdatedAt = &updatedAt

	if metadataJSON != "" && metadataJSON != "{}" {
		json.Unmarshal([]byte(metadataJSON), &system.Metadata)
	}

	return &system, nil
}

// Service Definition operations

func (s *PostgreSQLDB) CreateServiceDefinition(serviceDef *pkg.ServiceDefinition) error {
	query := `INSERT INTO service_definitions (service_definition, created_at, updated_at)
		VALUES ($1, $2, $3) RETURNING id`

	err := s.db.QueryRow(query, serviceDef.ServiceDefinition, serviceDef.CreatedAt, serviceDef.UpdatedAt).Scan(&serviceDef.ID)
	return err
}

func (s *PostgreSQLDB) GetServiceDefinitionByID(id int) (*pkg.ServiceDefinition, error) {
	query := `SELECT id, service_definition, created_at, updated_at FROM service_definitions WHERE id = $1`

	row := s.db.QueryRow(query, id)
	var serviceDef pkg.ServiceDefinition
	var createdAt, updatedAt time.Time

	err := row.Scan(&serviceDef.ID, &serviceDef.ServiceDefinition, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	serviceDef.CreatedAt = &createdAt
	serviceDef.UpdatedAt = &updatedAt

	return &serviceDef, nil
}

func (s *PostgreSQLDB) GetServiceDefinitionByName(name string) (*pkg.ServiceDefinition, error) {
	query := `SELECT id, service_definition, created_at, updated_at FROM service_definitions WHERE service_definition = $1`

	row := s.db.QueryRow(query, name)
	var serviceDef pkg.ServiceDefinition
	var createdAt, updatedAt time.Time

	err := row.Scan(&serviceDef.ID, &serviceDef.ServiceDefinition, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	serviceDef.CreatedAt = &createdAt
	serviceDef.UpdatedAt = &updatedAt

	return &serviceDef, nil
}

func (s *PostgreSQLDB) ListServiceDefinitions() ([]pkg.ServiceDefinition, error) {
	query := `SELECT id, service_definition, created_at, updated_at FROM service_definitions ORDER BY service_definition`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var serviceDefs []pkg.ServiceDefinition
	for rows.Next() {
		var serviceDef pkg.ServiceDefinition
		var createdAt, updatedAt time.Time

		err := rows.Scan(&serviceDef.ID, &serviceDef.ServiceDefinition, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		serviceDef.CreatedAt = &createdAt
		serviceDef.UpdatedAt = &updatedAt
		serviceDefs = append(serviceDefs, serviceDef)
	}

	return serviceDefs, nil
}

// Interface operations

func (s *PostgreSQLDB) CreateInterface(iface *pkg.Interface) error {
	query := `INSERT INTO interfaces (interface_name, created_at, updated_at) VALUES ($1, $2, $3) RETURNING id`

	err := s.db.QueryRow(query, iface.InterfaceName, iface.CreatedAt, iface.UpdatedAt).Scan(&iface.ID)
	return err
}

func (s *PostgreSQLDB) GetInterfaceByID(id int) (*pkg.Interface, error) {
	query := `SELECT id, interface_name, created_at, updated_at FROM interfaces WHERE id = $1`

	row := s.db.QueryRow(query, id)
	var iface pkg.Interface
	var createdAt, updatedAt time.Time

	err := row.Scan(&iface.ID, &iface.InterfaceName, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	iface.CreatedAt = &createdAt
	iface.UpdatedAt = &updatedAt

	return &iface, nil
}

func (s *PostgreSQLDB) GetInterfaceByName(name string) (*pkg.Interface, error) {
	query := `SELECT id, interface_name, created_at, updated_at FROM interfaces WHERE interface_name = $1`

	row := s.db.QueryRow(query, name)
	var iface pkg.Interface
	var createdAt, updatedAt time.Time

	err := row.Scan(&iface.ID, &iface.InterfaceName, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	iface.CreatedAt = &createdAt
	iface.UpdatedAt = &updatedAt

	return &iface, nil
}

func (s *PostgreSQLDB) ListInterfaces() ([]pkg.Interface, error) {
	query := `SELECT id, interface_name, created_at, updated_at FROM interfaces ORDER BY interface_name`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var interfaces []pkg.Interface
	for rows.Next() {
		var iface pkg.Interface
		var createdAt, updatedAt time.Time

		err := rows.Scan(&iface.ID, &iface.InterfaceName, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		iface.CreatedAt = &createdAt
		iface.UpdatedAt = &updatedAt
		interfaces = append(interfaces, iface)
	}

	return interfaces, nil
}

// Service operations - Simplified implementation for basic functionality
// Note: This is a basic implementation. For production, you'd want more sophisticated
// service management with proper interface linking, etc.

func (s *PostgreSQLDB) CreateService(service *pkg.Service) error {
	// Start a transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Serialize metadata
	metadataJSON := "{}"
	if service.Metadata != nil {
		if data, err := json.Marshal(service.Metadata); err == nil {
			metadataJSON = string(data)
		}
	}

	// Parse end of validity if provided
	var endOfValidity *time.Time
	if service.EndOfValidity != nil {
		endOfValidity = service.EndOfValidity
	}

	// Insert service into services table
	query := `INSERT INTO services (service_definition_id, provider_id, service_uri, end_of_validity, secure, metadata, version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`

	err = tx.QueryRow(query, service.ServiceDefinition.ID, service.Provider.ID, service.ServiceUri,
		endOfValidity, service.Secure, metadataJSON, service.Version, service.CreatedAt, service.UpdatedAt).Scan(&service.ID)
	if err != nil {
		return fmt.Errorf("failed to insert service: %w", err)
	}

	// Insert interface relationships
	for _, iface := range service.Interfaces {
		interfaceQuery := `INSERT INTO service_interfaces (service_id, interface_id) VALUES ($1, $2)`
		_, err = tx.Exec(interfaceQuery, service.ID, iface.ID)
		if err != nil {
			return fmt.Errorf("failed to insert service interface relationship: %w", err)
		}
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (s *PostgreSQLDB) GetServiceByID(id int) (*pkg.Service, error) {
	// Query to get service with joined system and service definition data
	query := `
		SELECT 
			s.id, s.service_uri, s.end_of_validity, s.secure, s.metadata, s.version, s.created_at, s.updated_at,
			sd.id, sd.service_definition, sd.created_at, sd.updated_at,
			sys.id, sys.system_name, sys.address, sys.port, sys.authentication_info, sys.metadata, sys.created_at, sys.updated_at
		FROM services s
		JOIN service_definitions sd ON s.service_definition_id = sd.id
		JOIN systems sys ON s.provider_id = sys.id
		WHERE s.id = $1`

	row := s.db.QueryRow(query, id)

	var service pkg.Service
	var serviceMetadataJSON, systemMetadataJSON string
	var serviceCreatedAt, serviceUpdatedAt, sdCreatedAt, sdUpdatedAt, sysCreatedAt, sysUpdatedAt time.Time
	var endOfValidity *time.Time

	err := row.Scan(
		&service.ID, &service.ServiceUri, &endOfValidity, &service.Secure, &serviceMetadataJSON, &service.Version, &serviceCreatedAt, &serviceUpdatedAt,
		&service.ServiceDefinition.ID, &service.ServiceDefinition.ServiceDefinition, &sdCreatedAt, &sdUpdatedAt,
		&service.Provider.ID, &service.Provider.SystemName, &service.Provider.Address, &service.Provider.Port, &service.Provider.AuthenticationInfo, &systemMetadataJSON, &sysCreatedAt, &sysUpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get service: %w", err)
	}

	// Set timestamps
	service.CreatedAt = &serviceCreatedAt
	service.UpdatedAt = &serviceUpdatedAt
	service.EndOfValidity = endOfValidity
	service.ServiceDefinition.CreatedAt = &sdCreatedAt
	service.ServiceDefinition.UpdatedAt = &sdUpdatedAt
	service.Provider.CreatedAt = &sysCreatedAt
	service.Provider.UpdatedAt = &sysUpdatedAt

	// Parse metadata
	if serviceMetadataJSON != "" && serviceMetadataJSON != "{}" {
		json.Unmarshal([]byte(serviceMetadataJSON), &service.Metadata)
	}
	if systemMetadataJSON != "" && systemMetadataJSON != "{}" {
		json.Unmarshal([]byte(systemMetadataJSON), &service.Provider.Metadata)
	}

	// Get interfaces for this service
	interfaceQuery := `
		SELECT i.id, i.interface_name, i.created_at, i.updated_at
		FROM interfaces i
		JOIN service_interfaces si ON i.id = si.interface_id
		WHERE si.service_id = $1`

	interfaceRows, err := s.db.Query(interfaceQuery, service.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to query service interfaces: %w", err)
	}
	defer interfaceRows.Close()

	var interfaces []pkg.Interface
	for interfaceRows.Next() {
		var iface pkg.Interface
		var ifaceCreatedAt, ifaceUpdatedAt time.Time

		err := interfaceRows.Scan(&iface.ID, &iface.InterfaceName, &ifaceCreatedAt, &ifaceUpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan interface row: %w", err)
		}

		iface.CreatedAt = &ifaceCreatedAt
		iface.UpdatedAt = &ifaceUpdatedAt
		interfaces = append(interfaces, iface)
	}

	service.Interfaces = interfaces
	return &service, nil
}

func (s *PostgreSQLDB) GetServicesByProvider(providerID int) ([]pkg.Service, error) {
	return nil, fmt.Errorf("service operations not fully implemented in database layer - registry handles this")
}

func (s *PostgreSQLDB) GetServicesByDefinition(serviceDefinition string) ([]pkg.Service, error) {
	return nil, fmt.Errorf("service operations not fully implemented in database layer - registry handles this")
}

func (s *PostgreSQLDB) UpdateService(service *pkg.Service) error {
	return fmt.Errorf("service operations not fully implemented in database layer - registry handles this")
}

func (s *PostgreSQLDB) DeleteServiceByID(id int) error {
	query := `DELETE FROM services WHERE id = $1`
	_, err := s.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}
	return nil
}

func (s *PostgreSQLDB) DeleteServiceByParams(systemName, serviceURI, serviceDefinition, address string, port int) error {
	return fmt.Errorf("service operations not fully implemented in database layer - registry handles this")
}

func (s *PostgreSQLDB) ListServices(sortField, direction string) ([]pkg.Service, error) {
	// Whitelist allowed sort fields to prevent SQL injection
	safeSortFields := map[string]string{
		"id":        "s.id",
		"createdAt": "s.created_at",
		"updatedAt": "s.updated_at",
		"uri":       "s.service_uri",
		"version":   "s.version",
	}

	// Get safe sort field or default
	orderBy, ok := safeSortFields[sortField]
	if !ok {
		orderBy = "s.id" // Default sort
	}

	// Validate direction
	if direction != "ASC" && direction != "DESC" {
		direction = "ASC" // Default direction
	}

	// Query to get services with joined system and service definition data
	query := fmt.Sprintf(`
		SELECT 
			s.id, s.service_uri, s.end_of_validity, s.secure, s.metadata, s.version, s.created_at, s.updated_at,
			sd.id, sd.service_definition, sd.created_at, sd.updated_at,
			sys.id, sys.system_name, sys.address, sys.port, sys.authentication_info, sys.metadata, sys.created_at, sys.updated_at
		FROM services s
		JOIN service_definitions sd ON s.service_definition_id = sd.id
		JOIN systems sys ON s.provider_id = sys.id
		ORDER BY %s %s`, orderBy, direction)

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query services: %w", err)
	}
	defer rows.Close()

	var services []pkg.Service
	for rows.Next() {
		var service pkg.Service
		var serviceMetadataJSON, systemMetadataJSON string
		var serviceCreatedAt, serviceUpdatedAt, sdCreatedAt, sdUpdatedAt, sysCreatedAt, sysUpdatedAt time.Time
		var endOfValidity *time.Time

		err := rows.Scan(
			&service.ID, &service.ServiceUri, &endOfValidity, &service.Secure, &serviceMetadataJSON, &service.Version, &serviceCreatedAt, &serviceUpdatedAt,
			&service.ServiceDefinition.ID, &service.ServiceDefinition.ServiceDefinition, &sdCreatedAt, &sdUpdatedAt,
			&service.Provider.ID, &service.Provider.SystemName, &service.Provider.Address, &service.Provider.Port, &service.Provider.AuthenticationInfo, &systemMetadataJSON, &sysCreatedAt, &sysUpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan service row: %w", err)
		}

		// Set timestamps
		service.CreatedAt = &serviceCreatedAt
		service.UpdatedAt = &serviceUpdatedAt
		service.EndOfValidity = endOfValidity
		service.ServiceDefinition.CreatedAt = &sdCreatedAt
		service.ServiceDefinition.UpdatedAt = &sdUpdatedAt
		service.Provider.CreatedAt = &sysCreatedAt
		service.Provider.UpdatedAt = &sysUpdatedAt

		// Parse metadata
		if serviceMetadataJSON != "" && serviceMetadataJSON != "{}" {
			json.Unmarshal([]byte(serviceMetadataJSON), &service.Metadata)
		}
		if systemMetadataJSON != "" && systemMetadataJSON != "{}" {
			json.Unmarshal([]byte(systemMetadataJSON), &service.Provider.Metadata)
		}

		// Get interfaces for this service
		interfaceQuery := `
			SELECT i.id, i.interface_name, i.created_at, i.updated_at
			FROM interfaces i
			JOIN service_interfaces si ON i.id = si.interface_id
			WHERE si.service_id = $1`

		interfaceRows, err := s.db.Query(interfaceQuery, service.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to query service interfaces: %w", err)
		}

		var interfaces []pkg.Interface
		for interfaceRows.Next() {
			var iface pkg.Interface
			var ifaceCreatedAt, ifaceUpdatedAt time.Time

			err := interfaceRows.Scan(&iface.ID, &iface.InterfaceName, &ifaceCreatedAt, &ifaceUpdatedAt)
			if err != nil {
				interfaceRows.Close()
				return nil, fmt.Errorf("failed to scan interface row: %w", err)
			}

			iface.CreatedAt = &ifaceCreatedAt
			iface.UpdatedAt = &ifaceUpdatedAt
			interfaces = append(interfaces, iface)
		}
		interfaceRows.Close()

		service.Interfaces = interfaces
		services = append(services, service)
	}

	return services, nil
}

// Authorization operations - Simplified implementation

func (s *PostgreSQLDB) CreateAuthorization(auth *pkg.Authorization) error {
	// Start a transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert authorization into authorizations table
	query := `INSERT INTO authorizations (consumer_id, provider_id, service_definition_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`

	err = tx.QueryRow(query, auth.ConsumerSystem.ID, auth.ProviderSystem.ID, auth.ServiceDefinition.ID,
		auth.CreatedAt, auth.UpdatedAt).Scan(&auth.ID)
	if err != nil {
		return fmt.Errorf("failed to insert authorization: %w", err)
	}

	// Insert interface relationships
	for _, iface := range auth.Interfaces {
		interfaceQuery := `INSERT INTO authorization_interfaces (authorization_id, interface_id) VALUES ($1, $2)`
		_, err = tx.Exec(interfaceQuery, auth.ID, iface.ID)
		if err != nil {
			return fmt.Errorf("failed to insert authorization interface relationship: %w", err)
		}
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (s *PostgreSQLDB) GetAuthorizationByID(id int) (*pkg.Authorization, error) {
	// Query to get authorization with joined consumer, provider, and service definition data
	query := `
		SELECT 
			a.id, a.created_at, a.updated_at,
			consumer.id, consumer.system_name, consumer.address, consumer.port, consumer.authentication_info, consumer.metadata, consumer.created_at, consumer.updated_at,
			provider.id, provider.system_name, provider.address, provider.port, provider.authentication_info, provider.metadata, provider.created_at, provider.updated_at,
			sd.id, sd.service_definition, sd.created_at, sd.updated_at
		FROM authorizations a
		JOIN systems consumer ON a.consumer_id = consumer.id
		JOIN systems provider ON a.provider_id = provider.id
		JOIN service_definitions sd ON a.service_definition_id = sd.id
		WHERE a.id = $1`

	row := s.db.QueryRow(query, id)

	var auth pkg.Authorization
	var consumerMetadataJSON, providerMetadataJSON string
	var authCreatedAt, authUpdatedAt, consumerCreatedAt, consumerUpdatedAt, providerCreatedAt, providerUpdatedAt, sdCreatedAt, sdUpdatedAt time.Time

	err := row.Scan(
		&auth.ID, &authCreatedAt, &authUpdatedAt,
		&auth.ConsumerSystem.ID, &auth.ConsumerSystem.SystemName, &auth.ConsumerSystem.Address, &auth.ConsumerSystem.Port, &auth.ConsumerSystem.AuthenticationInfo, &consumerMetadataJSON, &consumerCreatedAt, &consumerUpdatedAt,
		&auth.ProviderSystem.ID, &auth.ProviderSystem.SystemName, &auth.ProviderSystem.Address, &auth.ProviderSystem.Port, &auth.ProviderSystem.AuthenticationInfo, &providerMetadataJSON, &providerCreatedAt, &providerUpdatedAt,
		&auth.ServiceDefinition.ID, &auth.ServiceDefinition.ServiceDefinition, &sdCreatedAt, &sdUpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get authorization: %w", err)
	}

	// Set timestamps
	auth.CreatedAt = &authCreatedAt
	auth.UpdatedAt = &authUpdatedAt
	auth.ConsumerSystem.CreatedAt = &consumerCreatedAt
	auth.ConsumerSystem.UpdatedAt = &consumerUpdatedAt
	auth.ProviderSystem.CreatedAt = &providerCreatedAt
	auth.ProviderSystem.UpdatedAt = &providerUpdatedAt
	auth.ServiceDefinition.CreatedAt = &sdCreatedAt
	auth.ServiceDefinition.UpdatedAt = &sdUpdatedAt

	// Parse metadata
	if consumerMetadataJSON != "" && consumerMetadataJSON != "{}" {
		json.Unmarshal([]byte(consumerMetadataJSON), &auth.ConsumerSystem.Metadata)
	}
	if providerMetadataJSON != "" && providerMetadataJSON != "{}" {
		json.Unmarshal([]byte(providerMetadataJSON), &auth.ProviderSystem.Metadata)
	}

	// Get interfaces for this authorization
	interfaceQuery := `
		SELECT i.id, i.interface_name, i.created_at, i.updated_at
		FROM interfaces i
		JOIN authorization_interfaces ai ON i.id = ai.interface_id
		WHERE ai.authorization_id = $1`

	interfaceRows, err := s.db.Query(interfaceQuery, auth.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to query authorization interfaces: %w", err)
	}
	defer interfaceRows.Close()

	var interfaces []pkg.Interface
	for interfaceRows.Next() {
		var iface pkg.Interface
		var ifaceCreatedAt, ifaceUpdatedAt time.Time

		err := interfaceRows.Scan(&iface.ID, &iface.InterfaceName, &ifaceCreatedAt, &ifaceUpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan interface row: %w", err)
		}

		iface.CreatedAt = &ifaceCreatedAt
		iface.UpdatedAt = &ifaceUpdatedAt
		interfaces = append(interfaces, iface)
	}

	auth.Interfaces = interfaces
	return &auth, nil
}

func (s *PostgreSQLDB) GetAuthorizationsByConsumer(consumerID int) ([]pkg.Authorization, error) {
	return nil, fmt.Errorf("authorization operations not fully implemented in database layer - registry handles this")
}

func (s *PostgreSQLDB) GetAuthorizationsByProvider(providerID int) ([]pkg.Authorization, error) {
	return nil, fmt.Errorf("authorization operations not fully implemented in database layer - registry handles this")
}

func (s *PostgreSQLDB) DeleteAuthorizationByID(id int) error {
	query := `DELETE FROM authorizations WHERE id = $1`
	_, err := s.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete authorization: %w", err)
	}
	return nil
}

func (s *PostgreSQLDB) ListAuthorizations(sortField, direction string) ([]pkg.Authorization, error) {
	// Whitelist allowed sort fields to prevent SQL injection
	safeSortFields := map[string]string{
		"id":        "a.id",
		"createdAt": "a.created_at",
		"updatedAt": "a.updated_at",
	}

	// Get safe sort field or default
	orderBy, ok := safeSortFields[sortField]
	if !ok {
		orderBy = "a.id" // Default sort
	}

	// Validate direction
	if direction != "ASC" && direction != "DESC" {
		direction = "ASC" // Default direction
	}

	// Query to get authorizations with joined consumer, provider, and service definition data
	query := fmt.Sprintf(`
		SELECT 
			a.id, a.created_at, a.updated_at,
			consumer.id, consumer.system_name, consumer.address, consumer.port, consumer.authentication_info, consumer.metadata, consumer.created_at, consumer.updated_at,
			provider.id, provider.system_name, provider.address, provider.port, provider.authentication_info, provider.metadata, provider.created_at, provider.updated_at,
			sd.id, sd.service_definition, sd.created_at, sd.updated_at
		FROM authorizations a
		JOIN systems consumer ON a.consumer_id = consumer.id
		JOIN systems provider ON a.provider_id = provider.id
		JOIN service_definitions sd ON a.service_definition_id = sd.id
		ORDER BY %s %s`, orderBy, direction)

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query authorizations: %w", err)
	}
	defer rows.Close()

	var authorizations []pkg.Authorization
	for rows.Next() {
		var auth pkg.Authorization
		var consumerMetadataJSON, providerMetadataJSON string
		var authCreatedAt, authUpdatedAt, consumerCreatedAt, consumerUpdatedAt, providerCreatedAt, providerUpdatedAt, sdCreatedAt, sdUpdatedAt time.Time

		err := rows.Scan(
			&auth.ID, &authCreatedAt, &authUpdatedAt,
			&auth.ConsumerSystem.ID, &auth.ConsumerSystem.SystemName, &auth.ConsumerSystem.Address, &auth.ConsumerSystem.Port, &auth.ConsumerSystem.AuthenticationInfo, &consumerMetadataJSON, &consumerCreatedAt, &consumerUpdatedAt,
			&auth.ProviderSystem.ID, &auth.ProviderSystem.SystemName, &auth.ProviderSystem.Address, &auth.ProviderSystem.Port, &auth.ProviderSystem.AuthenticationInfo, &providerMetadataJSON, &providerCreatedAt, &providerUpdatedAt,
			&auth.ServiceDefinition.ID, &auth.ServiceDefinition.ServiceDefinition, &sdCreatedAt, &sdUpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan authorization row: %w", err)
		}

		// Set timestamps
		auth.CreatedAt = &authCreatedAt
		auth.UpdatedAt = &authUpdatedAt
		auth.ConsumerSystem.CreatedAt = &consumerCreatedAt
		auth.ConsumerSystem.UpdatedAt = &consumerUpdatedAt
		auth.ProviderSystem.CreatedAt = &providerCreatedAt
		auth.ProviderSystem.UpdatedAt = &providerUpdatedAt
		auth.ServiceDefinition.CreatedAt = &sdCreatedAt
		auth.ServiceDefinition.UpdatedAt = &sdUpdatedAt

		// Parse metadata
		if consumerMetadataJSON != "" && consumerMetadataJSON != "{}" {
			json.Unmarshal([]byte(consumerMetadataJSON), &auth.ConsumerSystem.Metadata)
		}
		if providerMetadataJSON != "" && providerMetadataJSON != "{}" {
			json.Unmarshal([]byte(providerMetadataJSON), &auth.ProviderSystem.Metadata)
		}

		// Get interfaces for this authorization
		interfaceQuery := `
			SELECT i.id, i.interface_name, i.created_at, i.updated_at
			FROM interfaces i
			JOIN authorization_interfaces ai ON i.id = ai.interface_id
			WHERE ai.authorization_id = $1`

		interfaceRows, err := s.db.Query(interfaceQuery, auth.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to query authorization interfaces: %w", err)
		}

		var interfaces []pkg.Interface
		for interfaceRows.Next() {
			var iface pkg.Interface
			var ifaceCreatedAt, ifaceUpdatedAt time.Time

			err := interfaceRows.Scan(&iface.ID, &iface.InterfaceName, &ifaceCreatedAt, &ifaceUpdatedAt)
			if err != nil {
				interfaceRows.Close()
				return nil, fmt.Errorf("failed to scan interface row: %w", err)
			}

			iface.CreatedAt = &ifaceCreatedAt
			iface.UpdatedAt = &ifaceUpdatedAt
			interfaces = append(interfaces, iface)
		}
		interfaceRows.Close()

		auth.Interfaces = interfaces
		authorizations = append(authorizations, auth)
	}

	return authorizations, nil
}

func (s *PostgreSQLDB) CheckAuthorization(consumerID, providerID, serviceDefinitionID int, interfaceIDs []int) (bool, error) {
	// Check if there's an authorization rule that matches the consumer, provider, and service definition
	query := `
		SELECT COUNT(*) 
		FROM authorizations 
		WHERE consumer_id = $1 AND provider_id = $2 AND service_definition_id = $3`

	var count int
	err := s.db.QueryRow(query, consumerID, providerID, serviceDefinitionID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check authorization: %w", err)
	}

	if count == 0 {
		return false, nil // No authorization rule found
	}

	// If there are specific interface requirements, check if the authorization covers them
	if len(interfaceIDs) > 0 {
		// Get the authorization ID first
		var authID int
		authQuery := `SELECT id FROM authorizations WHERE consumer_id = $1 AND provider_id = $2 AND service_definition_id = $3`
		err := s.db.QueryRow(authQuery, consumerID, providerID, serviceDefinitionID).Scan(&authID)
		if err != nil {
			return false, fmt.Errorf("failed to get authorization ID: %w", err)
		}

		// Check if all required interfaces are authorized
		for _, interfaceID := range interfaceIDs {
			interfaceQuery := `
				SELECT COUNT(*) 
				FROM authorization_interfaces 
				WHERE authorization_id = $1 AND interface_id = $2`

			var interfaceCount int
			err := s.db.QueryRow(interfaceQuery, authID, interfaceID).Scan(&interfaceCount)
			if err != nil {
				return false, fmt.Errorf("failed to check interface authorization: %w", err)
			}

			if interfaceCount == 0 {
				return false, nil // Interface not authorized
			}
		}
	}

	return true, nil
}

// Metrics

func (s *PostgreSQLDB) GetMetrics() (*pkg.Metrics, error) {
	var metrics pkg.Metrics

	// Count systems
	row := s.db.QueryRow("SELECT COUNT(*) FROM systems")
	row.Scan(&metrics.TotalSystems)
	metrics.ActiveSystems = metrics.TotalSystems // All systems are considered active

	// Count services
	s.db.QueryRow("SELECT COUNT(*) FROM services").Scan(&metrics.TotalServices)
	metrics.ActiveServices = metrics.TotalServices // All services are considered active

	return &metrics, nil
}

func (s *PostgreSQLDB) Close() error {
	return s.db.Close()
}
