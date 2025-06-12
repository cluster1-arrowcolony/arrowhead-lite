package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type AuthManager struct {
	db         Database
	logger     *logrus.Logger
	jwtSecret  []byte
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
	if privateKeyPEM != nil {
		privateBlock, _ := pem.Decode(privateKeyPEM)
		if privateBlock == nil {
			return fmt.Errorf("failed to decode private key PEM")
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
		if err != nil {
			if key, err2 := x509.ParsePKCS8PrivateKey(privateBlock.Bytes); err2 == nil {
				if rsaKey, ok := key.(*rsa.PrivateKey); ok {
					privateKey = rsaKey
				} else {
					return fmt.Errorf("private key is not RSA")
				}
			} else {
				return fmt.Errorf("failed to parse private key: %w", err)
			}
		}
		a.privateKey = privateKey
	}

	if publicKeyPEM != nil {
		publicBlock, _ := pem.Decode(publicKeyPEM)
		if publicBlock == nil {
			return fmt.Errorf("failed to decode public key PEM")
		}

		publicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}

		if rsaKey, ok := publicKey.(*rsa.PublicKey); ok {
			a.publicKey = rsaKey
		} else {
			return fmt.Errorf("public key is not RSA")
		}
	}

	return nil
}

func (a *AuthManager) CreateAuthRule(req *pkg.AuthRequest) (*pkg.AuthRule, error) {
	consumer, err := a.db.GetNode(req.ConsumerID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to get consumer node")
		return nil, pkg.DatabaseError(err)
	}
	if consumer == nil {
		return nil, pkg.NotFoundError("Consumer node not found")
	}

	provider, err := a.db.GetNode(req.ProviderID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to get provider node")
		return nil, pkg.DatabaseError(err)
	}
	if provider == nil {
		return nil, pkg.NotFoundError("Provider node not found")
	}

	service, err := a.db.GetService(req.ServiceID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to get service")
		return nil, pkg.DatabaseError(err)
	}
	if service == nil {
		return nil, pkg.NotFoundError("Service not found")
	}

	if service.NodeID != req.ProviderID {
		return nil, pkg.BadRequestError("Service does not belong to the specified provider")
	}

	existing, err := a.db.GetAuthRules(req.ConsumerID, req.ProviderID, req.ServiceID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to check existing auth rules")
		return nil, pkg.DatabaseError(err)
	}

	if len(existing) > 0 {
		return nil, pkg.ConflictError("Authorization rule already exists")
	}

	rule := &pkg.AuthRule{
		ID:         uuid.New().String(),
		ConsumerID: req.ConsumerID,
		ProviderID: req.ProviderID,
		ServiceID:  req.ServiceID,
		CreatedAt:  time.Now(),
	}

	if err := a.db.CreateAuthRule(rule); err != nil {
		a.logger.WithError(err).Error("Failed to create auth rule")
		return nil, pkg.DatabaseError(err)
	}

	a.logger.WithFields(logrus.Fields{
		"rule_id":     rule.ID,
		"consumer_id": rule.ConsumerID,
		"provider_id": rule.ProviderID,
		"service_id":  rule.ServiceID,
	}).Info("Authorization rule created successfully")

	return rule, nil
}

func (a *AuthManager) DeleteAuthRule(ruleID string) error {
	existing, err := a.db.GetAuthRule(ruleID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to get auth rule")
		return pkg.DatabaseError(err)
	}

	if existing == nil {
		return pkg.NotFoundError("Authorization rule not found")
	}

	if err := a.db.DeleteAuthRule(ruleID); err != nil {
		a.logger.WithError(err).Error("Failed to delete auth rule")
		return pkg.DatabaseError(err)
	}

	a.logger.WithField("rule_id", ruleID).Info("Authorization rule deleted successfully")

	return nil
}

func (a *AuthManager) ListAuthRules() ([]*pkg.AuthRule, error) {
	rules, err := a.db.ListAuthRules()
	if err != nil {
		a.logger.WithError(err).Error("Failed to list auth rules")
		return nil, pkg.DatabaseError(err)
	}

	return rules, nil
}

func (a *AuthManager) ListAuthRulesWithNames() ([]*pkg.AuthRuleWithNames, error) {
	rules, err := a.db.ListAuthRules()
	if err != nil {
		a.logger.WithError(err).Error("Failed to list auth rules")
		return nil, pkg.DatabaseError(err)
	}

	var rulesWithNames []*pkg.AuthRuleWithNames
	for _, rule := range rules {
		ruleWithNames := &pkg.AuthRuleWithNames{
			ID:         rule.ID,
			ConsumerID: rule.ConsumerID,
			ProviderID: rule.ProviderID,
			ServiceID:  rule.ServiceID,
			CreatedAt:  rule.CreatedAt,
		}

		// Get consumer name
		if consumer, err := a.db.GetNode(rule.ConsumerID); err == nil && consumer != nil {
			ruleWithNames.ConsumerName = consumer.Name
		} else {
			ruleWithNames.ConsumerName = "Unknown"
		}

		// Get provider name
		if provider, err := a.db.GetNode(rule.ProviderID); err == nil && provider != nil {
			ruleWithNames.ProviderName = provider.Name
		} else {
			ruleWithNames.ProviderName = "Unknown"
		}

		// Get service name
		if service, err := a.db.GetService(rule.ServiceID); err == nil && service != nil {
			ruleWithNames.ServiceName = service.Name
		} else {
			ruleWithNames.ServiceName = "Unknown"
		}

		rulesWithNames = append(rulesWithNames, ruleWithNames)
	}

	return rulesWithNames, nil
}

func (a *AuthManager) CheckAuthorization(consumerID, providerID, serviceID string) (bool, error) {
	rules, err := a.db.GetAuthRules(consumerID, providerID, serviceID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to check authorization")
		return false, pkg.DatabaseError(err)
	}

	return len(rules) > 0, nil
}

func (a *AuthManager) AuthorizeServiceAccess(consumerID, serviceID string) (*pkg.ServiceResponse, error) {
	service, err := a.db.GetService(serviceID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to get service for authorization")
		return nil, pkg.DatabaseError(err)
	}

	if service == nil {
		return nil, pkg.NotFoundError("Service not found")
	}

	provider, err := a.db.GetNode(service.NodeID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to get provider node")
		return nil, pkg.DatabaseError(err)
	}

	if provider == nil {
		return nil, pkg.NotFoundError("Provider node not found")
	}

	authorized, err := a.CheckAuthorization(consumerID, service.NodeID, serviceID)
	if err != nil {
		return nil, err
	}

	if !authorized {
		return nil, pkg.ForbiddenError("Access denied: no authorization rule found")
	}

	accessToken, err := a.GenerateAccessToken(consumerID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to generate access token")
		accessToken = ""
	}

	endpoint := fmt.Sprintf("https://%s:%d%s", provider.Address, provider.Port, service.URI)

	response := &pkg.ServiceResponse{
		Service:     *service,
		Node:        *provider,
		AccessToken: accessToken,
		Endpoint:    endpoint,
		Authorization: map[string]string{
			"type":  "Bearer",
			"token": accessToken,
		},
		Metadata: service.Metadata,
	}

	a.logger.WithFields(logrus.Fields{
		"consumer_id": consumerID,
		"service_id":  serviceID,
		"provider_id": service.NodeID,
	}).Info("Service access authorized")

	return response, nil
}

func (a *AuthManager) VerifyCertificate(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	if time.Now().After(cert.NotAfter) {
		return "", fmt.Errorf("certificate has expired")
	}

	if time.Now().Before(cert.NotBefore) {
		return "", fmt.Errorf("certificate is not yet valid")
	}

	return cert.Subject.CommonName, nil
}
