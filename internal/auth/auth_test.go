package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDatabase for auth tests
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

// Helper function to generate test RSA keys
func generateTestKeys() (*rsa.PrivateKey, *rsa.PublicKey, []byte, []byte) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	publicKeyPKIX, _ := x509.MarshalPKIXPublicKey(publicKey)
	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyPKIX,
	}
	publicKeyBytes := pem.EncodeToMemory(publicKeyPEM)

	return privateKey, publicKey, privateKeyBytes, publicKeyBytes
}

func TestNewAuthManager(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()
	jwtSecret := []byte("test-secret")

	authManager := NewAuthManager(mockDB, logger, jwtSecret)

	assert.NotNil(t, authManager)
	assert.Equal(t, mockDB, authManager.db)
	assert.Equal(t, logger, authManager.logger)
	assert.Equal(t, jwtSecret, authManager.jwtSecret)
}

func TestSetKeys(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()
	authManager := NewAuthManager(mockDB, logger, []byte("secret"))

	_, _, privateKeyPEM, publicKeyPEM := generateTestKeys()

	err := authManager.SetKeys(privateKeyPEM, publicKeyPEM)

	assert.NoError(t, err)
	assert.NotNil(t, authManager.privateKey)
	assert.NotNil(t, authManager.publicKey)
}

func TestCreateAuthorization(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	authManager := NewAuthManager(mockDB, logger, []byte("secret"))

	t.Run("Successful Authorization Creation", func(t *testing.T) {
		now := time.Now()
		consumer := &pkg.System{
			ID:         1,
			SystemName: "consumer-system",
			Address:    "192.168.1.1",
			Port:       8001,
			CreatedAt:  &now,
		}

		provider := &pkg.System{
			ID:         2,
			SystemName: "provider-system",
			Address:    "192.168.1.2",
			Port:       8002,
			CreatedAt:  &now,
		}

		req := &pkg.AddAuthorizationRequest{
			ConsumerID:           1,
			ProviderIDs:          []int{2},
			ServiceDefinitionIDs: []int{1},
			InterfaceIDs:         []int{1},
		}

		mockDB.On("GetSystemByID", 1).Return(consumer, nil).Once()
		mockDB.On("GetSystemByID", 2).Return(provider, nil).Once()
		mockDB.On("CreateAuthorization", mock.AnythingOfType("*pkg.Authorization")).Return(nil).Once()

		result, err := authManager.CreateAuthorization(req)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, consumer.ID, result.ConsumerSystem.ID)
		assert.Equal(t, provider.ID, result.ProviderSystem.ID)
		mockDB.AssertExpectations(t)
	})

	t.Run("Consumer Not Found", func(t *testing.T) {
		req := &pkg.AddAuthorizationRequest{
			ConsumerID:           999,
			ProviderIDs:          []int{2},
			ServiceDefinitionIDs: []int{1},
			InterfaceIDs:         []int{1},
		}

		mockDB.On("GetSystemByID", 999).Return(nil, nil).Once()

		result, err := authManager.CreateAuthorization(req)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "Consumer system not found")
		mockDB.AssertExpectations(t)
	})

	t.Run("Provider Not Found", func(t *testing.T) {
		now := time.Now()
		consumer := &pkg.System{
			ID:         1,
			SystemName: "consumer-system",
			Address:    "192.168.1.1",
			Port:       8001,
			CreatedAt:  &now,
		}

		req := &pkg.AddAuthorizationRequest{
			ConsumerID:           1,
			ProviderIDs:          []int{999},
			ServiceDefinitionIDs: []int{1},
			InterfaceIDs:         []int{1},
		}

		mockDB.On("GetSystemByID", 1).Return(consumer, nil).Once()
		mockDB.On("GetSystemByID", 999).Return(nil, nil).Once()

		result, err := authManager.CreateAuthorization(req)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "Provider system not found")
		mockDB.AssertExpectations(t)
	})

	t.Run("Missing Required IDs", func(t *testing.T) {
		req := &pkg.AddAuthorizationRequest{
			ConsumerID:           1,
			ProviderIDs:          []int{},
			ServiceDefinitionIDs: []int{},
			InterfaceIDs:         []int{1},
		}

		now := time.Now()
		consumer := &pkg.System{
			ID:         1,
			SystemName: "consumer-system",
			Address:    "192.168.1.1",
			Port:       8001,
			CreatedAt:  &now,
		}

		mockDB.On("GetSystemByID", 1).Return(consumer, nil).Once()

		result, err := authManager.CreateAuthorization(req)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "Provider IDs and Service Definition IDs are required")
		mockDB.AssertExpectations(t)
	})
}

func TestAuthorizeServiceAccess(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	authManager := NewAuthManager(mockDB, logger, []byte("secret"))

	t.Run("Access Authorized", func(t *testing.T) {
		service := &pkg.Service{
			ID: 1,
			Provider: pkg.Provider{
				ID: 2,
			},
			ServiceDefinition: pkg.ServiceDefinition{
				ID: 3,
			},
		}

		mockDB.On("CheckAuthorization", 1, 2, 3, []int{}).Return(true, nil).Once()

		authorized, err := authManager.AuthorizeServiceAccess(1, service)

		assert.NoError(t, err)
		assert.True(t, authorized)
		mockDB.AssertExpectations(t)
	})

	t.Run("Access Denied", func(t *testing.T) {
		service := &pkg.Service{
			ID: 1,
			Provider: pkg.Provider{
				ID: 2,
			},
			ServiceDefinition: pkg.ServiceDefinition{
				ID: 3,
			},
		}

		mockDB.On("CheckAuthorization", 1, 2, 3, []int{}).Return(false, nil).Once()

		authorized, err := authManager.AuthorizeServiceAccess(1, service)

		assert.NoError(t, err)
		assert.False(t, authorized)
		mockDB.AssertExpectations(t)
	})

	t.Run("Database Error", func(t *testing.T) {
		service := &pkg.Service{
			ID: 1,
			Provider: pkg.Provider{
				ID: 2,
			},
			ServiceDefinition: pkg.ServiceDefinition{
				ID: 3,
			},
		}

		dbErr := fmt.Errorf("database connection failed")
		mockDB.On("CheckAuthorization", 1, 2, 3, []int{}).Return(false, dbErr).Once()

		authorized, err := authManager.AuthorizeServiceAccess(1, service)

		assert.Error(t, err)
		assert.False(t, authorized)
		mockDB.AssertExpectations(t)
	})
}

func TestGenerateServiceToken(t *testing.T) {
	mockDB := new(MockDatabase)
	logger := logrus.New()
	authManager := NewAuthManager(mockDB, logger, []byte("secret"))

	t.Run("Token Generation Success", func(t *testing.T) {
		_, _, privateKeyPEM, publicKeyPEM := generateTestKeys()
		err := authManager.SetKeys(privateKeyPEM, publicKeyPEM)
		assert.NoError(t, err)

		token, err := authManager.GenerateServiceToken(1, 2, 3)

		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token can be parsed
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return authManager.publicKey, nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)
	})

	t.Run("No Private Key Configured", func(t *testing.T) {
		authManager := NewAuthManager(mockDB, logger, []byte("secret"))

		token, err := authManager.GenerateServiceToken(1, 2, 3)

		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "auth manager is not configured with a private key")
	})
}
