package registry

import (
	"fmt"
	"testing"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDatabase is a mock implementation of the database.Database interface
type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) CreateSystem(system *pkg.System) error {
	args := m.Called(system)
	return args.Error(0)
}

func (m *MockDatabase) CreateSystemsBatch(systems []*pkg.System) error {
	args := m.Called(systems)
	return args.Error(0)
}

func (m *MockDatabase) GetSystemByID(id int) (*pkg.System, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pkg.System), args.Error(1)
}

func (m *MockDatabase) GetSystemByName(systemName string) (*pkg.System, error) {
	args := m.Called(systemName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pkg.System), args.Error(1)
}

func (m *MockDatabase) GetSystemByParams(systemName, address string, port int) (*pkg.System, error) {
	args := m.Called(systemName, address, port)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pkg.System), args.Error(1)
}

func (m *MockDatabase) UpdateSystem(system *pkg.System) error {
	args := m.Called(system)
	return args.Error(0)
}

func (m *MockDatabase) DeleteSystemByID(id int) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockDatabase) DeleteSystemByParams(systemName, address string, port int) error {
	args := m.Called(systemName, address, port)
	return args.Error(0)
}

func (m *MockDatabase) ListSystems(sortField, direction string) ([]pkg.System, error) {
	args := m.Called(sortField, direction)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]pkg.System), args.Error(1)
}

func (m *MockDatabase) CreateService(service *pkg.Service) error {
	args := m.Called(service)
	return args.Error(0)
}

func (m *MockDatabase) CreateServicesBatch(services []*pkg.Service) error {
	args := m.Called(services)
	return args.Error(0)
}

func (m *MockDatabase) GetServiceByID(id int) (*pkg.Service, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pkg.Service), args.Error(1)
}

func (m *MockDatabase) GetServicesByProvider(providerID int) ([]pkg.Service, error) {
	args := m.Called(providerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]pkg.Service), args.Error(1)
}

func (m *MockDatabase) GetServicesByDefinition(serviceDefinition string) ([]pkg.Service, error) {
	args := m.Called(serviceDefinition)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]pkg.Service), args.Error(1)
}

func (m *MockDatabase) UpdateService(service *pkg.Service) error {
	args := m.Called(service)
	return args.Error(0)
}

func (m *MockDatabase) DeleteServiceByID(id int) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockDatabase) DeleteServiceByParams(systemName, serviceURI, serviceDefinition, address string, port int) error {
	args := m.Called(systemName, serviceURI, serviceDefinition, address, port)
	return args.Error(0)
}

func (m *MockDatabase) ListServices(sortField, direction string) ([]pkg.Service, error) {
	args := m.Called(sortField, direction)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]pkg.Service), args.Error(1)
}

func (m *MockDatabase) CreateServiceDefinition(serviceDef *pkg.ServiceDefinition) error {
	args := m.Called(serviceDef)
	return args.Error(0)
}

func (m *MockDatabase) GetServiceDefinitionByID(id int) (*pkg.ServiceDefinition, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pkg.ServiceDefinition), args.Error(1)
}

func (m *MockDatabase) GetServiceDefinitionByName(name string) (*pkg.ServiceDefinition, error) {
	args := m.Called(name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pkg.ServiceDefinition), args.Error(1)
}

func (m *MockDatabase) ListServiceDefinitions() ([]pkg.ServiceDefinition, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]pkg.ServiceDefinition), args.Error(1)
}

func (m *MockDatabase) CreateInterface(iface *pkg.Interface) error {
	args := m.Called(iface)
	return args.Error(0)
}

func (m *MockDatabase) GetInterfaceByID(id int) (*pkg.Interface, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pkg.Interface), args.Error(1)
}

func (m *MockDatabase) GetInterfaceByName(name string) (*pkg.Interface, error) {
	args := m.Called(name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pkg.Interface), args.Error(1)
}

func (m *MockDatabase) ListInterfaces() ([]pkg.Interface, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]pkg.Interface), args.Error(1)
}

func (m *MockDatabase) CreateAuthorization(auth *pkg.Authorization) error {
	args := m.Called(auth)
	return args.Error(0)
}

func (m *MockDatabase) CreateAuthorizationsBatch(auths []*pkg.Authorization) error {
	args := m.Called(auths)
	return args.Error(0)
}

func (m *MockDatabase) GetAuthorizationByID(id int) (*pkg.Authorization, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pkg.Authorization), args.Error(1)
}

func (m *MockDatabase) GetAuthorizationsByConsumer(consumerID int) ([]pkg.Authorization, error) {
	args := m.Called(consumerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]pkg.Authorization), args.Error(1)
}

func (m *MockDatabase) GetAuthorizationsByProvider(providerID int) ([]pkg.Authorization, error) {
	args := m.Called(providerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]pkg.Authorization), args.Error(1)
}

func (m *MockDatabase) DeleteAuthorizationByID(id int) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockDatabase) ListAuthorizations(sortField, direction string) ([]pkg.Authorization, error) {
	args := m.Called(sortField, direction)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]pkg.Authorization), args.Error(1)
}

func (m *MockDatabase) CheckAuthorization(consumerID, providerID, serviceDefinitionID int, interfaceIDs []int) (bool, error) {
	args := m.Called(consumerID, providerID, serviceDefinitionID, interfaceIDs)
	return args.Bool(0), args.Error(1)
}

func (m *MockDatabase) GetMetrics() (*pkg.Metrics, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pkg.Metrics), args.Error(1)
}

func (m *MockDatabase) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewRegistry(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()

	registry := NewRegistry(mockDB, logger)

	assert.NotNil(t, registry)
	assert.Equal(t, mockDB, registry.db)
	assert.Equal(t, logger, registry.logger)
}

func TestRegisterSystem(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	registry := NewRegistry(mockDB, logger)

	t.Run("New System Registration", func(t *testing.T) {
		req := &pkg.SystemRegistration{
			SystemName:         "test-system",
			Address:            "192.168.1.100",
			Port:               8080,
			AuthenticationInfo: "test-auth-info",
			Metadata:           map[string]string{"env": "test"},
		}

		// Mock that system doesn't exist
		mockDB.On("GetSystemByParams", "test-system", "192.168.1.100", 8080).Return(nil, pkg.NotFoundError("not found")).Once()

		// Mock successful batch creation
		mockDB.On("CreateSystemsBatch", mock.AnythingOfType("[]*pkg.System")).Return(nil).Once()

		result, err := registry.RegisterSystem(req)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, req.SystemName, result.SystemName)
		assert.Equal(t, req.Address, result.Address)
		assert.Equal(t, req.Port, result.Port)
		mockDB.AssertExpectations(t)
	})

	t.Run("Existing System Update", func(t *testing.T) {
		now := time.Now()
		existingSystem := &pkg.System{
			ID:                 1,
			SystemName:         "existing-system",
			Address:            "192.168.1.101",
			Port:               8081,
			AuthenticationInfo: "old-auth",
			CreatedAt:          &now,
			UpdatedAt:          &now,
		}

		req := &pkg.SystemRegistration{
			SystemName:         "existing-system",
			Address:            "192.168.1.101",
			Port:               8081,
			AuthenticationInfo: "new-auth",
			Metadata:           map[string]string{"updated": "true"},
		}

		// Mock that system exists
		mockDB.On("GetSystemByParams", "existing-system", "192.168.1.101", 8081).Return(existingSystem, nil).Once()

		// Mock successful update
		mockDB.On("UpdateSystem", mock.AnythingOfType("*pkg.System")).Return(nil).Once()

		result, err := registry.RegisterSystem(req)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, existingSystem.ID, result.ID)
		assert.Equal(t, req.AuthenticationInfo, result.AuthenticationInfo)
		mockDB.AssertExpectations(t)
	})
}

func TestRegisterSystemsBatch(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	registry := NewRegistry(mockDB, logger)

	t.Run("Batch Registration Success", func(t *testing.T) {
		reqs := []pkg.SystemRegistration{
			{
				SystemName: "system1",
				Address:    "192.168.1.1",
				Port:       8001,
			},
			{
				SystemName: "system2",
				Address:    "192.168.1.2",
				Port:       8002,
			},
		}

		// Mock that systems don't exist
		mockDB.On("GetSystemByParams", "system1", "192.168.1.1", 8001).Return(nil, pkg.NotFoundError("not found")).Once()
		mockDB.On("GetSystemByParams", "system2", "192.168.1.2", 8002).Return(nil, pkg.NotFoundError("not found")).Once()

		// Mock successful batch creation
		mockDB.On("CreateSystemsBatch", mock.AnythingOfType("[]*pkg.System")).Return(nil).Once()

		results, err := registry.RegisterSystemsBatch(reqs)

		assert.NoError(t, err)
		assert.Len(t, results, 2)
		assert.Equal(t, "system1", results[0].SystemName)
		assert.Equal(t, "system2", results[1].SystemName)
		mockDB.AssertExpectations(t)
	})
}

func TestUnregisterSystemByID(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	registry := NewRegistry(mockDB, logger)

	t.Run("Successful Unregistration", func(t *testing.T) {
		systemID := 1
		mockDB.On("DeleteSystemByID", systemID).Return(nil).Once()

		err := registry.UnregisterSystemByID(systemID)

		assert.NoError(t, err)
		mockDB.AssertExpectations(t)
	})

	t.Run("Database Error", func(t *testing.T) {
		systemID := 2
		dbErr := fmt.Errorf("database connection failed")
		mockDB.On("DeleteSystemByID", systemID).Return(dbErr).Once()

		err := registry.UnregisterSystemByID(systemID)

		assert.Error(t, err)
		mockDB.AssertExpectations(t)
	})
}

func TestGetSystemByID(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	registry := NewRegistry(mockDB, logger)

	t.Run("System Found", func(t *testing.T) {
		now := time.Now()
		expectedSystem := &pkg.System{
			ID:         1,
			SystemName: "test-system",
			Address:    "192.168.1.100",
			Port:       8080,
			CreatedAt:  &now,
		}

		mockDB.On("GetSystemByID", 1).Return(expectedSystem, nil).Once()

		result, err := registry.GetSystemByID(1)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, expectedSystem.ID, result.ID)
		assert.Equal(t, expectedSystem.SystemName, result.SystemName)
		mockDB.AssertExpectations(t)
	})

	t.Run("System Not Found", func(t *testing.T) {
		mockDB.On("GetSystemByID", 999).Return(nil, pkg.NotFoundError("system not found")).Once()

		result, err := registry.GetSystemByID(999)

		assert.Error(t, err)
		assert.Nil(t, result)
		mockDB.AssertExpectations(t)
	})
}

func TestListSystems(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	registry := NewRegistry(mockDB, logger)

	t.Run("List Systems Success", func(t *testing.T) {
		now := time.Now()
		expectedSystems := []pkg.System{
			{
				ID:         1,
				SystemName: "system1",
				Address:    "192.168.1.1",
				Port:       8001,
				CreatedAt:  &now,
			},
			{
				ID:         2,
				SystemName: "system2",
				Address:    "192.168.1.2",
				Port:       8002,
				CreatedAt:  &now,
			},
		}

		mockDB.On("ListSystems", "id", "ASC").Return(expectedSystems, nil).Once()

		results, err := registry.ListSystems()

		assert.NoError(t, err)
		assert.Len(t, results, 2)
		assert.Equal(t, expectedSystems[0].SystemName, results[0].SystemName)
		assert.Equal(t, expectedSystems[1].SystemName, results[1].SystemName)
		mockDB.AssertExpectations(t)
	})

	t.Run("Empty List", func(t *testing.T) {
		mockDB.On("ListSystems", "id", "ASC").Return([]pkg.System{}, nil).Once()

		results, err := registry.ListSystems()

		assert.NoError(t, err)
		assert.Empty(t, results)
		mockDB.AssertExpectations(t)
	})
}
