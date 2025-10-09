// Package auth implements the Arrowhead Authorization core system.
//
// This package handles authentication and authorization for the Arrowhead local cloud,
// managing JWT token generation/validation and authorization rule enforcement.
// It implements both token-based and certificate-based authentication mechanisms
// as specified in the Arrowhead Framework 4.x.
//
// Key responsibilities:
//   - JWT token generation and validation using RSA signatures
//   - Authorization rule creation and enforcement
//   - Service access permission checks
//   - Integration with mTLS certificate authentication
package auth

import (
	"crypto/rsa"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/internal/database"
	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// Claims represents JWT token claims for Arrowhead authentication.
// These claims are embedded in JWT tokens issued for service access.
type Claims struct {
	SystemID   int    `json:"system_id,omitempty"`   // Database ID of the authenticated system
	SystemName string `json:"system_name,omitempty"` // Name of the authenticated system
	IsAdmin    bool   `json:"is_admin,omitempty"`    // Whether this is an admin token
	AdminUser  string `json:"admin_user,omitempty"`  // Admin username if IsAdmin is true
	jwt.RegisteredClaims
}

// AuthManager handles authentication and authorization for the Arrowhead local cloud.
// It manages JWT token generation/validation and authorization rule enforcement.
type AuthManager struct {
	db         database.Database
	logger     *logrus.Logger
	jwtSecret  []byte
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewAuthManager creates a new authorization manager with the provided database,
// logger, and JWT secret. For production use with RSA-signed tokens, call SetKeys
// after creation to configure the RSA key pair.
func NewAuthManager(db database.Database, logger *logrus.Logger, jwtSecret []byte) *AuthManager {
	return &AuthManager{db: db, logger: logger, jwtSecret: jwtSecret}
}

// SetKeys configures the RSA key pair for JWT token signing and validation.
// The private key is used for signing tokens, and the public key for validation.
//
// Parameters:
//   - privateKeyPEM: PEM-encoded RSA private key (for token signing)
//   - publicKeyPEM: PEM-encoded RSA public key (for token validation)
//
// Either parameter can be nil if only signing or only validation is needed.
//
// Returns an error if the provided PEM data cannot be parsed as valid RSA keys.
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

// Create a new Authorization rule
func (a *AuthManager) CreateAuthorization(req *pkg.AddAuthorizationRequest) (*pkg.Authorization, error) {
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

	provider, err := a.db.GetSystemByID(providerID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to get provider system")
		return nil, pkg.DatabaseError(err)
	}
	if provider == nil {
		return nil, pkg.NotFoundError("Provider system not found")
	}

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

// AuthorizeServiceAccess checks whether a consumer system is authorized to access
// a specific service. This validates that an authorization rule exists granting
// the consumer access to the provider's service.
//
// Parameters:
//   - consumerID: Database ID of the consuming system
//   - service: The service being accessed
//
// Returns true if an authorization rule exists, false otherwise.
// Returns an error if the database query fails.
func (a *AuthManager) AuthorizeServiceAccess(consumerID int, service *pkg.Service) (bool, error) {
	// Check authorization
	authorized, err := a.db.CheckAuthorization(consumerID, service.Provider.ID, service.ServiceDefinition.ID, []int{})
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

// Create a JWT token for service access (public method)
func (a *AuthManager) GenerateServiceToken(consumerID, providerID, serviceID int) (string, error) {
	return a.generateServiceToken(consumerID, providerID, serviceID)
}

// Create a JWT token for service access
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

// ValidateToken verifies and parses a JWT token string.
// The token must be signed with the configured RSA private key.
//
// Returns the parsed Claims if the token is valid and not expired.
//
// Returns pkg.UnauthorizedError if:
//   - The token signature is invalid
//   - The token is expired
//   - The token claims are malformed
//   - No public key is configured for validation
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
