package orchestration

import (
	"testing"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/auth"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDatabase for orchestration tests
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

// MockAuthManager for orchestration tests
type MockAuthManager struct {
	mock.Mock
}

func (m *MockAuthManager) AuthorizeServiceAccess(consumerID int, service *pkg.Service) (bool, error) {
	args := m.Called(consumerID, service)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthManager) GenerateServiceToken(consumerID, providerID, serviceID int) (string, error) {
	args := m.Called(consumerID, providerID, serviceID)
	return args.String(0), args.Error(1)
}

func TestNewOrchestrator(t *testing.T) {
	mockDB := new(MockDatabase)
	mockAuth := auth.NewAuthManager(mockDB, logrus.New(), []byte("secret"))
	logger := logrus.New()

	orchestrator := NewOrchestrator(mockDB, mockAuth, logger)

	assert.NotNil(t, orchestrator)
	assert.Equal(t, mockDB, orchestrator.db)
	assert.NotNil(t, orchestrator.authManager)
	assert.Equal(t, logger, orchestrator.logger)
}

func TestOrchestrate(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockAuth := auth.NewAuthManager(mockDB, logger, []byte("secret"))
	orchestrator := NewOrchestrator(mockDB, mockAuth, logger)

	t.Run("Successful Orchestration", func(t *testing.T) {
		now := time.Now()
		services := []pkg.Service{
			{
				ID: 1,
				ServiceDefinition: pkg.ServiceDefinition{
					ID:                1,
					ServiceDefinition: "temperature-sensor",
				},
				Provider: pkg.Provider{
					ID:         1,
					SystemName: "sensor-1",
					Address:    "192.168.1.10",
					Port:       8080,
				},
				ServiceUri: "/temperature",
				Secure:     "CERTIFICATE",
				Interfaces: []pkg.Interface{
					{ID: 1, InterfaceName: "HTTP-SECURE-JSON"},
				},
				CreatedAt: &now,
			},
			{
				ID: 2,
				ServiceDefinition: pkg.ServiceDefinition{
					ID:                1,
					ServiceDefinition: "temperature-sensor",
				},
				Provider: pkg.Provider{
					ID:         2,
					SystemName: "sensor-2",
					Address:    "192.168.1.11",
					Port:       8081,
				},
				ServiceUri: "/temp",
				Secure:     "CERTIFICATE",
				Interfaces: []pkg.Interface{
					{ID: 1, InterfaceName: "HTTP-SECURE-JSON"},
				},
				CreatedAt: &now,
			},
		}

		req := &pkg.OrchestrationRequest{
			RequesterSystem: pkg.RequesterSystem{
				SystemName: "consumer-system",
				Address:    "192.168.1.100",
				Port:       9000,
			},
			RequestedService: pkg.RequestedService{
				ServiceDefinitionRequirement: "temperature-sensor",
				InterfaceRequirements:        []string{"HTTP-SECURE-JSON"},
			},
			OrchestrationFlags: pkg.OrchestrationFlags{
				Matchmaking: true,
			},
		}

		mockDB.On("ListServices", "id", "ASC").Return(services, nil).Once()
		mockDB.On("GetSystemByName", "consumer-system").Return(&pkg.System{
			ID:         3,
			SystemName: "consumer-system",
			Address:    "192.168.1.100",
			Port:       9000,
		}, nil).Maybe() // Called multiple times during orchestration
		mockDB.On("CheckAuthorization", 3, 1, 1, mock.Anything).Return(true, nil).Once()
		mockDB.On("CheckAuthorization", 3, 2, 1, mock.Anything).Return(true, nil).Once()

		response, err := orchestrator.Orchestrate(req)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Len(t, response.Response, 2)
		assert.Equal(t, "sensor-1", response.Response[0].Provider.SystemName)
		assert.Equal(t, "sensor-2", response.Response[1].Provider.SystemName)
		mockDB.AssertExpectations(t)
	})

	t.Run("No Matching Services", func(t *testing.T) {
		req := &pkg.OrchestrationRequest{
			RequesterSystem: pkg.RequesterSystem{
				SystemName: "consumer-system",
				Address:    "192.168.1.100",
				Port:       9000,
			},
			RequestedService: pkg.RequestedService{
				ServiceDefinitionRequirement: "non-existent-service",
			},
		}

		mockDB.On("ListServices", "id", "ASC").Return([]pkg.Service{}, nil).Once()

		response, err := orchestrator.Orchestrate(req)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Empty(t, response.Response)
		mockDB.AssertExpectations(t)
	})

	t.Run("Service Filtering by Interface", func(t *testing.T) {
		now := time.Now()
		services := []pkg.Service{
			{
				ID: 1,
				ServiceDefinition: pkg.ServiceDefinition{
					ID:                1,
					ServiceDefinition: "test-service",
				},
				Provider: pkg.Provider{
					ID:         1,
					SystemName: "provider-1",
					Address:    "192.168.1.10",
					Port:       8080,
				},
				ServiceUri: "/api",
				Interfaces: []pkg.Interface{
					{ID: 1, InterfaceName: "HTTP-SECURE-JSON"},
				},
				CreatedAt: &now,
			},
			{
				ID: 2,
				ServiceDefinition: pkg.ServiceDefinition{
					ID:                1,
					ServiceDefinition: "test-service",
				},
				Provider: pkg.Provider{
					ID:         2,
					SystemName: "provider-2",
					Address:    "192.168.1.11",
					Port:       8081,
				},
				ServiceUri: "/api",
				Interfaces: []pkg.Interface{
					{ID: 2, InterfaceName: "HTTP-INSECURE-JSON"},
				},
				CreatedAt: &now,
			},
		}

		req := &pkg.OrchestrationRequest{
			RequesterSystem: pkg.RequesterSystem{
				SystemName: "consumer-system",
			},
			RequestedService: pkg.RequestedService{
				ServiceDefinitionRequirement: "test-service",
				InterfaceRequirements:        []string{"HTTP-SECURE-JSON"},
			},
		}

		mockDB.On("ListServices", "id", "ASC").Return(services, nil).Once()
		mockDB.On("GetSystemByName", "consumer-system").Return(&pkg.System{
			ID:         3,
			SystemName: "consumer-system",
		}, nil).Maybe() // Called multiple times during orchestration
		mockDB.On("CheckAuthorization", 3, 1, 1, mock.Anything).Return(true, nil).Once()

		response, err := orchestrator.Orchestrate(req)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Len(t, response.Response, 1)
		assert.Equal(t, "provider-1", response.Response[0].Provider.SystemName)
		mockDB.AssertExpectations(t)
	})

	t.Run("Authorization Filtering", func(t *testing.T) {
		now := time.Now()
		services := []pkg.Service{
			{
				ID: 1,
				ServiceDefinition: pkg.ServiceDefinition{
					ID:                1,
					ServiceDefinition: "test-service",
				},
				Provider: pkg.Provider{
					ID:         1,
					SystemName: "authorized-provider",
					Address:    "192.168.1.10",
					Port:       8080,
				},
				ServiceUri: "/api",
				CreatedAt:  &now,
			},
			{
				ID: 2,
				ServiceDefinition: pkg.ServiceDefinition{
					ID:                1,
					ServiceDefinition: "test-service",
				},
				Provider: pkg.Provider{
					ID:         2,
					SystemName: "unauthorized-provider",
					Address:    "192.168.1.11",
					Port:       8081,
				},
				ServiceUri: "/api",
				CreatedAt:  &now,
			},
		}

		req := &pkg.OrchestrationRequest{
			RequesterSystem: pkg.RequesterSystem{
				SystemName: "consumer-system",
			},
			RequestedService: pkg.RequestedService{
				ServiceDefinitionRequirement: "test-service",
			},
			OrchestrationFlags: pkg.OrchestrationFlags{
				Matchmaking: true,
			},
		}

		mockDB.On("ListServices", "id", "ASC").Return(services, nil).Once()
		mockDB.On("GetSystemByName", "consumer-system").Return(&pkg.System{
			ID:         3,
			SystemName: "consumer-system",
		}, nil).Maybe() // Called multiple times during orchestration
		mockDB.On("CheckAuthorization", 3, 1, 1, mock.Anything).Return(true, nil).Once()
		mockDB.On("CheckAuthorization", 3, 2, 1, mock.Anything).Return(false, nil).Once()

		response, err := orchestrator.Orchestrate(req)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Len(t, response.Response, 1)
		assert.Equal(t, "authorized-provider", response.Response[0].Provider.SystemName)
		mockDB.AssertExpectations(t)
	})
}