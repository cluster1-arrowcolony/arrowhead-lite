package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAuthTest(t *testing.T) (*internal.AuthManager, internal.Database) {
	db := setupTestStorage(t)
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	authManager := internal.NewAuthManager(db, logger, []byte("test-secret-key"))
	return authManager, db
}

func generateTestKeys(t *testing.T) ([]byte, []byte) {
	// Generate RSA key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Convert private key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Convert public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKeyPEM, publicKeyPEM
}

func TestAuthManager_SetKeys(t *testing.T) {
	authManager, _ := setupAuthTest(t)

	privateKeyPEM, publicKeyPEM := generateTestKeys(t)

	err := authManager.SetKeys(privateKeyPEM, publicKeyPEM)
	assert.NoError(t, err, "SetKeys should succeed with valid keys")
}

func TestAuthManager_SetKeys_InvalidPrivateKey(t *testing.T) {
	authManager, _ := setupAuthTest(t)

	invalidPEM := []byte("invalid-pem-data")

	err := authManager.SetKeys(invalidPEM, nil)
	assert.Error(t, err, "SetKeys should fail with invalid private key")
	assert.Contains(t, err.Error(), "failed to decode private key PEM")
}

func TestAuthManager_GenerateAccessToken(t *testing.T) {
	authManager, db := setupAuthTest(t)

	// Create a test node
	node := &pkg.Node{
		ID:        "test-node-1",
		Name:      "Test Node",
		Address:   "localhost",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	err := db.CreateNode(node)
	require.NoError(t, err)

	// Generate token
	token, err := authManager.GenerateAccessToken(node.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, token, "Token should not be empty")

	// Validate token structure
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-secret-key"), nil
	})

	require.NoError(t, err)
	assert.True(t, parsedToken.Valid, "Token should be valid")

	// Check claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok, "Claims should be accessible")

	assert.Equal(t, node.ID, claims["node_id"])
	assert.Equal(t, node.Name, claims["node_name"])

	// Check is_admin claim if it exists, otherwise assume false
	if isAdmin, exists := claims["is_admin"]; exists && isAdmin != nil {
		assert.False(t, isAdmin.(bool))
	}
}

func TestAuthManager_GenerateAccessToken_NodeNotFound(t *testing.T) {
	authManager, _ := setupAuthTest(t)

	token, err := authManager.GenerateAccessToken("non-existent-node")
	assert.Error(t, err, "Should fail for non-existent node")
	assert.Empty(t, token, "Token should be empty on error")
	assert.Contains(t, err.Error(), "Node not found")
}

func TestAuthManager_GenerateAdminToken(t *testing.T) {
	authManager, _ := setupAuthTest(t)

	username := "admin-user"
	token, err := authManager.GenerateAdminToken(username)
	require.NoError(t, err)
	assert.NotEmpty(t, token, "Admin token should not be empty")

	// Validate token structure
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-secret-key"), nil
	})

	require.NoError(t, err)
	assert.True(t, parsedToken.Valid, "Admin token should be valid")

	// Check claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok, "Claims should be accessible")

	assert.True(t, claims["is_admin"].(bool))
	assert.Equal(t, username, claims["admin_user"])
}

func TestAuthManager_ValidateToken(t *testing.T) {
	authManager, db := setupAuthTest(t)

	// Create a test node
	node := &pkg.Node{
		ID:        "test-node-1",
		Name:      "Test Node",
		Address:   "localhost",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	err := db.CreateNode(node)
	require.NoError(t, err)

	// Generate and validate token
	token, err := authManager.GenerateAccessToken(node.ID)
	require.NoError(t, err)

	claims, err := authManager.ValidateToken(token)
	require.NoError(t, err)
	assert.NotNil(t, claims, "Claims should not be nil")

	assert.Equal(t, node.ID, claims.NodeID)
	assert.Equal(t, node.Name, claims.NodeName)
	assert.False(t, claims.IsAdmin)
}

func TestAuthManager_ValidateToken_Invalid(t *testing.T) {
	authManager, _ := setupAuthTest(t)

	invalidToken := "invalid.jwt.token"
	claims, err := authManager.ValidateToken(invalidToken)
	assert.Error(t, err, "Should fail for invalid token")
	assert.Nil(t, claims, "Claims should be nil for invalid token")
}

func TestAuthManager_ValidateToken_Expired(t *testing.T) {
	authManager, db := setupAuthTest(t)

	// Create a test node
	node := &pkg.Node{
		ID:        "test-node-1",
		Name:      "Test Node",
		Address:   "localhost",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	err := db.CreateNode(node)
	require.NoError(t, err)

	// Create an expired token manually
	claims := &internal.Claims{
		NodeID:   node.ID,
		NodeName: node.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Issuer:    "arrowhead-lite",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("test-secret-key"))
	require.NoError(t, err)

	// Try to validate expired token
	validatedClaims, err := authManager.ValidateToken(tokenString)
	assert.Error(t, err, "Should fail for expired token")
	assert.Nil(t, validatedClaims, "Claims should be nil for expired token")
	assert.Contains(t, err.Error(), "Invalid token")
}

func TestAuthManager_CreateAuthRule(t *testing.T) {
	authManager, db := setupAuthTest(t)

	// Setup test nodes and service
	consumer := &pkg.Node{
		ID:        "consumer-1",
		Name:      "Consumer Node",
		Address:   "localhost",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	provider := &pkg.Node{
		ID:        "provider-1",
		Name:      "Provider Node",
		Address:   "localhost",
		Port:      8081,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	service := &pkg.Service{
		ID:         "service-1",
		Name:       "test-service",
		NodeID:     "provider-1",
		Definition: "test-definition",
		URI:        "/test",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(provider))
	require.NoError(t, db.CreateService(service))

	// Create auth rule
	authReq := &pkg.AuthRequest{
		ConsumerID: consumer.ID,
		ProviderID: provider.ID,
		ServiceID:  service.ID,
	}
	authRule, err := authManager.CreateAuthRule(authReq)
	require.NoError(t, err)
	assert.NotNil(t, authRule, "Auth rule should not be nil")

	assert.Equal(t, consumer.ID, authRule.ConsumerID)
	assert.Equal(t, provider.ID, authRule.ProviderID)
	assert.Equal(t, service.ID, authRule.ServiceID)
	assert.NotEmpty(t, authRule.ID, "Auth rule ID should not be empty")
}

func TestAuthManager_CreateAuthRule_ConsumerNotFound(t *testing.T) {
	authManager, db := setupAuthTest(t)

	provider := &pkg.Node{
		ID:        "provider-1",
		Name:      "Provider Node",
		Address:   "localhost",
		Port:      8081,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	service := &pkg.Service{
		ID:         "service-1",
		Name:       "test-service",
		NodeID:     "provider-1",
		Definition: "test-definition",
		URI:        "/test",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(provider))
	require.NoError(t, db.CreateService(service))

	authReq := &pkg.AuthRequest{
		ConsumerID: "non-existent-consumer",
		ProviderID: provider.ID,
		ServiceID:  service.ID,
	}
	authRule, err := authManager.CreateAuthRule(authReq)
	assert.Error(t, err, "Should fail for non-existent consumer")
	assert.Nil(t, authRule, "Auth rule should be nil on error")
	assert.Contains(t, err.Error(), "Consumer node not found")
}

func TestAuthManager_CheckAuthorization(t *testing.T) {
	authManager, db := setupAuthTest(t)

	// Setup test nodes and service
	consumer := &pkg.Node{
		ID:        "consumer-1",
		Name:      "Consumer Node",
		Address:   "localhost",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	provider := &pkg.Node{
		ID:        "provider-1",
		Name:      "Provider Node",
		Address:   "localhost",
		Port:      8081,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	service := &pkg.Service{
		ID:         "service-1",
		Name:       "test-service",
		NodeID:     "provider-1",
		Definition: "test-definition",
		URI:        "/test",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(provider))
	require.NoError(t, db.CreateService(service))

	// Initially no authorization
	authorized, err := authManager.CheckAuthorization(consumer.ID, provider.ID, service.ID)
	require.NoError(t, err)
	assert.False(t, authorized, "Should not be authorized initially")

	// Create auth rule
	authReq := &pkg.AuthRequest{
		ConsumerID: consumer.ID,
		ProviderID: provider.ID,
		ServiceID:  service.ID,
	}
	_, err = authManager.CreateAuthRule(authReq)
	require.NoError(t, err)

	// Now should be authorized
	authorized, err = authManager.CheckAuthorization(consumer.ID, provider.ID, service.ID)
	require.NoError(t, err)
	assert.True(t, authorized, "Should be authorized after creating auth rule")
}

func TestAuthManager_DeleteAuthRule(t *testing.T) {
	authManager, db := setupAuthTest(t)

	// Setup test nodes and service
	consumer := &pkg.Node{
		ID:        "consumer-1",
		Name:      "Consumer Node",
		Address:   "localhost",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	provider := &pkg.Node{
		ID:        "provider-1",
		Name:      "Provider Node",
		Address:   "localhost",
		Port:      8081,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	service := &pkg.Service{
		ID:         "service-1",
		Name:       "test-service",
		NodeID:     "provider-1",
		Definition: "test-definition",
		URI:        "/test",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(provider))
	require.NoError(t, db.CreateService(service))

	// Create auth rule
	authReq := &pkg.AuthRequest{
		ConsumerID: consumer.ID,
		ProviderID: provider.ID,
		ServiceID:  service.ID,
	}
	authRule, err := authManager.CreateAuthRule(authReq)
	require.NoError(t, err)

	// Verify it exists
	authorized, err := authManager.CheckAuthorization(consumer.ID, provider.ID, service.ID)
	require.NoError(t, err)
	assert.True(t, authorized, "Should be authorized")

	// Delete auth rule
	err = authManager.DeleteAuthRule(authRule.ID)
	require.NoError(t, err)

	// Verify it's gone
	authorized, err = authManager.CheckAuthorization(consumer.ID, provider.ID, service.ID)
	require.NoError(t, err)
	assert.False(t, authorized, "Should not be authorized after deletion")
}

func TestAuthManager_ListAuthRules(t *testing.T) {
	authManager, db := setupAuthTest(t)

	// Setup test nodes and services
	consumer := &pkg.Node{
		ID:        "consumer-1",
		Name:      "Consumer Node",
		Address:   "localhost",
		Port:      8080,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	provider1 := &pkg.Node{
		ID:        "provider-1",
		Name:      "Provider Node 1",
		Address:   "localhost",
		Port:      8081,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	provider2 := &pkg.Node{
		ID:        "provider-2",
		Name:      "Provider Node 2",
		Address:   "localhost",
		Port:      8082,
		Status:    pkg.NodeStatusOnline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	service1 := &pkg.Service{
		ID:         "service-1",
		Name:       "test-service-1",
		NodeID:     "provider-1",
		Definition: "test-definition-1",
		URI:        "/test1",
		Method:     "GET",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	service2 := &pkg.Service{
		ID:         "service-2",
		Name:       "test-service-2",
		NodeID:     "provider-2",
		Definition: "test-definition-2",
		URI:        "/test2",
		Method:     "POST",
		Version:    "1.0",
		Status:     pkg.ServiceStatusActive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	require.NoError(t, db.CreateNode(consumer))
	require.NoError(t, db.CreateNode(provider1))
	require.NoError(t, db.CreateNode(provider2))
	require.NoError(t, db.CreateService(service1))
	require.NoError(t, db.CreateService(service2))

	// Initially no rules
	rules, err := authManager.ListAuthRules()
	require.NoError(t, err)
	assert.Len(t, rules, 0, "Should have no auth rules initially")

	// Create auth rules
	authReq1 := &pkg.AuthRequest{
		ConsumerID: consumer.ID,
		ProviderID: provider1.ID,
		ServiceID:  service1.ID,
	}
	_, err = authManager.CreateAuthRule(authReq1)
	require.NoError(t, err)

	authReq2 := &pkg.AuthRequest{
		ConsumerID: consumer.ID,
		ProviderID: provider2.ID,
		ServiceID:  service2.ID,
	}
	_, err = authManager.CreateAuthRule(authReq2)
	require.NoError(t, err)

	// List rules
	rules, err = authManager.ListAuthRules()
	require.NoError(t, err)
	assert.Len(t, rules, 2, "Should have 2 auth rules")

	// Verify rule contents
	ruleIDs := make(map[string]bool)
	for _, rule := range rules {
		ruleIDs[rule.ID] = true
		assert.Equal(t, consumer.ID, rule.ConsumerID)
		assert.Contains(t, []string{provider1.ID, provider2.ID}, rule.ProviderID)
		assert.Contains(t, []string{service1.ID, service2.ID}, rule.ServiceID)
	}

	assert.Len(t, ruleIDs, 2, "Should have 2 unique rule IDs")
}
