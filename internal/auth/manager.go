package auth

import (
	"crypto/rsa"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// Claims represents JWT token claims
type Claims struct {
	SystemID   int    `json:"system_id,omitempty"`
	SystemName string `json:"system_name,omitempty"`
	IsAdmin    bool   `json:"is_admin,omitempty"`
	AdminUser  string `json:"admin_user,omitempty"`
	jwt.RegisteredClaims
}

type AuthManager struct {
	db        Database
	logger    *logrus.Logger
	jwtSecret []byte
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func newAuthManager(db Database, logger *logrus.Logger, jwtSecret []byte) *AuthManager {
	return &AuthManager{
		db:        db,
		logger:    logger,
		jwtSecret: jwtSecret,
	}
}

func (a *AuthManager) SetKeys(privateKeyPEM, publicKeyPEM []byte) error {
	if len(privateKeyPEM) > 0 {
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
		if err != nil {
			return err
		}
		a.privateKey = privateKey
	}

	if len(publicKeyPEM) > 0 {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
		if err != nil {
			return err
		}
		a.publicKey = publicKey
	}

	return nil
}

// CreateAuthorization creates a new authorization rule using Arrowhead 4.x models
func (a *AuthManager) CreateAuthorization(req *pkg.AddAuthorizationRequest) (*pkg.Authorization, error) {
	// Validate consumer system exists
	consumer, err := a.db.GetSystemByID(req.ConsumerID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to get consumer system")
		return nil, pkg.DatabaseError(err)
	}
	if consumer == nil {
		return nil, pkg.NotFoundError("Consumer system not found")
	}

	// For now, just handle the first provider and service definition
	// TODO: Handle multiple providers and service definitions
	if len(req.ProviderIDs) == 0 || len(req.ServiceDefinitionIDs) == 0 {
		return nil, pkg.BadRequestError("Provider IDs and Service Definition IDs are required")
	}

	providerID := req.ProviderIDs[0]
	serviceDefinitionID := req.ServiceDefinitionIDs[0]

	// Validate provider system exists
	provider, err := a.db.GetSystemByID(providerID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to get provider system")
		return nil, pkg.DatabaseError(err)
	}
	if provider == nil {
		return nil, pkg.NotFoundError("Provider system not found")
	}

	// Create authorization record using the full structures
	now := time.Now()
	authorization := &pkg.Authorization{
		ConsumerSystem: *consumer,
		ProviderSystem: pkg.Provider{
			ID:                 provider.ID,
			SystemName:         provider.SystemName,
			Address:            provider.Address,
			Port:               provider.Port,
			AuthenticationInfo: provider.AuthenticationInfo,
			CreatedAt:          provider.CreatedAt,
			UpdatedAt:          provider.UpdatedAt,
		},
		ServiceDefinition: pkg.ServiceDefinition{
			ID: serviceDefinitionID, // Will need to fetch this properly
		},
		CreatedAt: &now,
		UpdatedAt: &now,
	}

	if err := a.db.CreateAuthorization(authorization); err != nil {
		a.logger.WithError(err).Error("Failed to create authorization")
		return nil, pkg.DatabaseError(err)
	}

	a.logger.WithFields(logrus.Fields{
		"consumer_id":           req.ConsumerID,
		"provider_id":           providerID,
		"service_definition_id": serviceDefinitionID,
	}).Info("Authorization created")

	return authorization, nil
}

// AuthorizeServiceAccess checks if a consumer is authorized to access a service
func (a *AuthManager) AuthorizeServiceAccess(consumerID int, service *pkg.Service) (bool, error) {
	// Check authorization
	authorized, err := a.CheckAuthorization(consumerID, service.Provider.ID, service.ServiceDefinition.ID)
	if err != nil {
		a.logger.WithError(err).WithFields(logrus.Fields{
			"consumer_id": consumerID,
			"service_id":  service.ID,
		}).Error("Failed to check authorization")
		return false, err
	}

	if !authorized {
		a.logger.WithFields(logrus.Fields{
			"consumer_id": consumerID,
			"service_id":  service.ID,
		}).Warn("Access denied: no authorization rule found")
		return false, nil
	}

	return true, nil
}

// CheckAuthorization checks if consumer is authorized to access provider's service
func (a *AuthManager) CheckAuthorization(consumerID, providerID, serviceDefinitionID int) (bool, error) {
	return a.db.CheckAuthorization(consumerID, providerID, serviceDefinitionID, []int{})
}

// DeleteAuthorization removes an authorization rule
func (a *AuthManager) DeleteAuthorization(authorizationID int) error {
	return a.db.DeleteAuthorizationByID(authorizationID)
}

// ListAuthorizations returns all authorization rules
func (a *AuthManager) ListAuthorizations() ([]pkg.Authorization, error) {
	return a.db.ListAuthorizations("id", "ASC")
}

// GenerateServiceToken creates a JWT token for service access (public method)
func (a *AuthManager) GenerateServiceToken(consumerID, providerID, serviceID int) (string, error) {
	return a.generateServiceToken(consumerID, providerID, serviceID)
}

// generateServiceToken creates a JWT token for service access
func (a *AuthManager) generateServiceToken(consumerID, providerID, serviceID int) (string, error) {
	if a.privateKey == nil {
		return "", pkg.ConfigurationError("auth manager is not configured with a private key for JWT signing")
	}

	claims := jwt.MapClaims{
		"sub":         consumerID,
		"provider_id": providerID,
		"service_id":  serviceID,
		"iat":         time.Now().Unix(),
		"exp":         time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(a.privateKey)
}

// ValidateToken validates a JWT token
func (a *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		// Check that the token's signing method is what you expect
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, pkg.UnauthorizedError("unexpected signing method: " + token.Header["alg"].(string))
		}
		if a.publicKey == nil {
			return nil, pkg.ConfigurationError("auth manager is not configured with a public key for JWT validation")
		}
		return a.publicKey, nil
	})

	if err != nil {
		return nil, pkg.UnauthorizedError("Invalid token: " + err.Error())
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, pkg.UnauthorizedError("Invalid token claims")
}
