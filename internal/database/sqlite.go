package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	_ "github.com/mattn/go-sqlite3"
)

type SQLite struct {
	db *sql.DB
}

func NewSQLiteDB(connection string) (*SQLite, error) {
	db, err := sql.Open("sqlite3", connection)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &SQLite{db: db}
	if err := storage.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return storage, nil
}

func (s *SQLite) initSchema() error {
	schema := `
	-- Arrowhead 4.x Systems table
	CREATE TABLE IF NOT EXISTS systems (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		system_name TEXT UNIQUE NOT NULL,
		address TEXT NOT NULL,
		port INTEGER NOT NULL,
		authentication_info TEXT,
		metadata TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		UNIQUE(system_name, address, port)
	);

	-- Service Definitions table
	CREATE TABLE IF NOT EXISTS service_definitions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		service_definition TEXT UNIQUE NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	-- Interfaces table
	CREATE TABLE IF NOT EXISTS interfaces (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		interface_name TEXT UNIQUE NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	-- Services table (Arrowhead 4.x)
	CREATE TABLE IF NOT EXISTS services (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		service_definition_id INTEGER NOT NULL,
		provider_id INTEGER NOT NULL,
		service_uri TEXT NOT NULL,
		end_of_validity DATETIME,
		secure TEXT NOT NULL DEFAULT 'TOKEN',
		metadata TEXT,
		version INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
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
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		consumer_id INTEGER NOT NULL,
		provider_id INTEGER NOT NULL,
		service_definition_id INTEGER NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
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

func (s *SQLite) CreateSystem(system *pkg.System) error {
	metadataJSON := "{}"
	if system.Metadata != nil {
		if data, err := json.Marshal(system.Metadata); err == nil {
			metadataJSON = string(data)
		}
	}

	query := `INSERT INTO systems (system_name, address, port, authentication_info, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query, system.SystemName, system.Address, system.Port,
		system.AuthenticationInfo, metadataJSON, system.CreatedAt, system.UpdatedAt)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	system.ID = int(id)

	return nil
}

func (s *SQLite) GetSystemByID(id int) (*pkg.System, error) {
	query := `SELECT id, system_name, address, port, authentication_info, metadata, created_at, updated_at
		FROM systems WHERE id = ?`

	row := s.db.QueryRow(query, id)
	return s.scanSystem(row)
}

func (s *SQLite) GetSystemByName(systemName string) (*pkg.System, error) {
	query := `SELECT id, system_name, address, port, authentication_info, metadata, created_at, updated_at
		FROM systems WHERE system_name = ?`

	row := s.db.QueryRow(query, systemName)
	return s.scanSystem(row)
}

func (s *SQLite) GetSystemByParams(systemName, address string, port int) (*pkg.System, error) {
	query := `SELECT id, system_name, address, port, authentication_info, metadata, created_at, updated_at
		FROM systems WHERE system_name = ? AND address = ? AND port = ?`

	row := s.db.QueryRow(query, systemName, address, port)
	return s.scanSystem(row)
}

func (s *SQLite) UpdateSystem(system *pkg.System) error {
	metadataJSON := "{}"
	if system.Metadata != nil {
		if data, err := json.Marshal(system.Metadata); err == nil {
			metadataJSON = string(data)
		}
	}

	query := `UPDATE systems SET system_name = ?, address = ?, port = ?, authentication_info = ?,
		metadata = ?, updated_at = ? WHERE id = ?`

	_, err := s.db.Exec(query, system.SystemName, system.Address, system.Port,
		system.AuthenticationInfo, metadataJSON, system.UpdatedAt, system.ID)
	return err
}

func (s *SQLite) DeleteSystemByID(id int) error {
	query := `DELETE FROM systems WHERE id = ?`
	_, err := s.db.Exec(query, id)
	return err
}

func (s *SQLite) DeleteSystemByParams(systemName, address string, port int) error {
	query := `DELETE FROM systems WHERE system_name = ? AND address = ? AND port = ?`
	_, err := s.db.Exec(query, systemName, address, port)
	return err
}

func (s *SQLite) ListSystems(sortField, direction string) ([]pkg.System, error) {
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

func (s *SQLite) scanSystem(row *sql.Row) (*pkg.System, error) {
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

func (s *SQLite) scanSystemFromRows(rows *sql.Rows) (*pkg.System, error) {
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

func (s *SQLite) CreateServiceDefinition(serviceDef *pkg.ServiceDefinition) error {
	query := `INSERT INTO service_definitions (service_definition, created_at, updated_at)
		VALUES (?, ?, ?)`

	result, err := s.db.Exec(query, serviceDef.ServiceDefinition, serviceDef.CreatedAt, serviceDef.UpdatedAt)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	serviceDef.ID = int(id)

	return nil
}

func (s *SQLite) GetServiceDefinitionByID(id int) (*pkg.ServiceDefinition, error) {
	query := `SELECT id, service_definition, created_at, updated_at FROM service_definitions WHERE id = ?`

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

func (s *SQLite) GetServiceDefinitionByName(name string) (*pkg.ServiceDefinition, error) {
	query := `SELECT id, service_definition, created_at, updated_at FROM service_definitions WHERE service_definition = ?`

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

func (s *SQLite) ListServiceDefinitions() ([]pkg.ServiceDefinition, error) {
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

func (s *SQLite) CreateInterface(iface *pkg.Interface) error {
	query := `INSERT INTO interfaces (interface_name, created_at, updated_at) VALUES (?, ?, ?)`

	result, err := s.db.Exec(query, iface.InterfaceName, iface.CreatedAt, iface.UpdatedAt)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	iface.ID = int(id)

	return nil
}

func (s *SQLite) GetInterfaceByID(id int) (*pkg.Interface, error) {
	query := `SELECT id, interface_name, created_at, updated_at FROM interfaces WHERE id = ?`

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

func (s *SQLite) GetInterfaceByName(name string) (*pkg.Interface, error) {
	query := `SELECT id, interface_name, created_at, updated_at FROM interfaces WHERE interface_name = ?`

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

func (s *SQLite) ListInterfaces() ([]pkg.Interface, error) {
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

func (s *SQLite) CreateService(service *pkg.Service) error {
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := tx.Exec(query, service.ServiceDefinition.ID, service.Provider.ID, service.ServiceUri,
		endOfValidity, service.Secure, metadataJSON, service.Version, service.CreatedAt, service.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert service: %w", err)
	}

	// Get the inserted service ID
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get service ID: %w", err)
	}
	service.ID = int(id)

	// Insert interface relationships
	for _, iface := range service.Interfaces {
		interfaceQuery := `INSERT INTO service_interfaces (service_id, interface_id) VALUES (?, ?)`
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

func (s *SQLite) GetServiceByID(id int) (*pkg.Service, error) {
	// Query to get service with joined system and service definition data
	query := `
		SELECT 
			s.id, s.service_uri, s.end_of_validity, s.secure, s.metadata, s.version, s.created_at, s.updated_at,
			sd.id, sd.service_definition, sd.created_at, sd.updated_at,
			sys.id, sys.system_name, sys.address, sys.port, sys.authentication_info, sys.metadata, sys.created_at, sys.updated_at
		FROM services s
		JOIN service_definitions sd ON s.service_definition_id = sd.id
		JOIN systems sys ON s.provider_id = sys.id
		WHERE s.id = ?`

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
		WHERE si.service_id = ?`

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

func (s *SQLite) GetServicesByProvider(providerID int) ([]pkg.Service, error) {
	return nil, fmt.Errorf("service operations not fully implemented in database layer - registry handles this")
}

func (s *SQLite) GetServicesByDefinition(serviceDefinition string) ([]pkg.Service, error) {
	return nil, fmt.Errorf("service operations not fully implemented in database layer - registry handles this")
}

func (s *SQLite) UpdateService(service *pkg.Service) error {
	return fmt.Errorf("service operations not fully implemented in database layer - registry handles this")
}

func (s *SQLite) DeleteServiceByID(id int) error {
	query := `DELETE FROM services WHERE id = ?`
	_, err := s.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}
	return nil
}

func (s *SQLite) DeleteServiceByParams(systemName, serviceURI, serviceDefinition, address string, port int) error {
	return fmt.Errorf("service operations not fully implemented in database layer - registry handles this")
}

func (s *SQLite) ListServices(sortField, direction string) ([]pkg.Service, error) {
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
			WHERE si.service_id = ?`

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

func (s *SQLite) CreateAuthorization(auth *pkg.Authorization) error {
	// Start a transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert authorization into authorizations table
	query := `INSERT INTO authorizations (consumer_id, provider_id, service_definition_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)`

	result, err := tx.Exec(query, auth.ConsumerSystem.ID, auth.ProviderSystem.ID, auth.ServiceDefinition.ID,
		auth.CreatedAt, auth.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert authorization: %w", err)
	}

	// Get the inserted authorization ID
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get authorization ID: %w", err)
	}
	auth.ID = int(id)

	// Insert interface relationships
	for _, iface := range auth.Interfaces {
		interfaceQuery := `INSERT INTO authorization_interfaces (authorization_id, interface_id) VALUES (?, ?)`
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

func (s *SQLite) GetAuthorizationByID(id int) (*pkg.Authorization, error) {
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
		WHERE a.id = ?`

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
		WHERE ai.authorization_id = ?`

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

func (s *SQLite) GetAuthorizationsByConsumer(consumerID int) ([]pkg.Authorization, error) {
	return nil, fmt.Errorf("authorization operations not fully implemented in database layer - registry handles this")
}

func (s *SQLite) GetAuthorizationsByProvider(providerID int) ([]pkg.Authorization, error) {
	return nil, fmt.Errorf("authorization operations not fully implemented in database layer - registry handles this")
}

func (s *SQLite) DeleteAuthorizationByID(id int) error {
	query := `DELETE FROM authorizations WHERE id = ?`
	_, err := s.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete authorization: %w", err)
	}
	return nil
}

func (s *SQLite) ListAuthorizations(sortField, direction string) ([]pkg.Authorization, error) {
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
			WHERE ai.authorization_id = ?`

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

func (s *SQLite) CheckAuthorization(consumerID, providerID, serviceDefinitionID int, interfaceIDs []int) (bool, error) {
	// Check if there's an authorization rule that matches the consumer, provider, and service definition
	query := `
		SELECT COUNT(*) 
		FROM authorizations 
		WHERE consumer_id = ? AND provider_id = ? AND service_definition_id = ?`

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
		authQuery := `SELECT id FROM authorizations WHERE consumer_id = ? AND provider_id = ? AND service_definition_id = ?`
		err := s.db.QueryRow(authQuery, consumerID, providerID, serviceDefinitionID).Scan(&authID)
		if err != nil {
			return false, fmt.Errorf("failed to get authorization ID: %w", err)
		}

		// Check if all required interfaces are authorized
		for _, interfaceID := range interfaceIDs {
			interfaceQuery := `
				SELECT COUNT(*) 
				FROM authorization_interfaces 
				WHERE authorization_id = ? AND interface_id = ?`
			
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

func (s *SQLite) GetMetrics() (*pkg.Metrics, error) {
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

func (s *SQLite) Close() error {
	return s.db.Close()
}