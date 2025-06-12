package gateway

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/sirupsen/logrus"
)

// GatewaySecurityManager handles X.509 certificate management and security for gateways
type GatewaySecurityManager struct {
	config       Config
	logger       *logrus.Logger
	trustAnchors map[string]*x509.Certificate // Cloud ID -> Root Certificate
	caCerts      map[string]*x509.Certificate // Certificate hash -> CA Certificate
	privateKey   *rsa.PrivateKey
	certificate  *x509.Certificate
}

// TrustAnchor represents a trusted root certificate for a cloud
type TrustAnchor struct {
	CloudID     string
	Certificate *x509.Certificate
	PublicKey   crypto.PublicKey
	ValidFrom   time.Time
	ValidTo     time.Time
}

// CertificateValidationResult contains the result of certificate validation
type CertificateValidationResult struct {
	Valid        bool
	CloudID      string
	CommonName   string
	Organization string
	ValidFrom    time.Time
	ValidTo      time.Time
	ErrorMessage string
	TrustChain   []*x509.Certificate
}

// newGatewaySecurityManager creates a new gateway security manager
func newGatewaySecurityManager(config Config, logger *logrus.Logger) (*GatewaySecurityManager, error) {
	gsm := &GatewaySecurityManager{
		config:       config,
		logger:       logger,
		trustAnchors: make(map[string]*x509.Certificate),
		caCerts:      make(map[string]*x509.Certificate),
	}

	// Load gateway's own certificate and private key
	if err := gsm.loadGatewayCertificate(); err != nil {
		return nil, fmt.Errorf("failed to load gateway certificate: %w", err)
	}

	// Load trust anchors
	if err := gsm.loadTrustAnchors(); err != nil {
		return nil, fmt.Errorf("failed to load trust anchors: %w", err)
	}

	return gsm, nil
}

// ValidateCertificate validates an X.509 certificate for gateway communication
func (gsm *GatewaySecurityManager) ValidateCertificate(certPEM string) error {
	result := gsm.ValidateCertificateDetailed(certPEM)
	if !result.Valid {
		return fmt.Errorf("certificate validation failed: %s", result.ErrorMessage)
	}
	return nil
}

// ValidateCertificateDetailed performs detailed certificate validation
func (gsm *GatewaySecurityManager) ValidateCertificateDetailed(certPEM string) *CertificateValidationResult {
	result := &CertificateValidationResult{}

	// Parse certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		result.ErrorMessage = "failed to decode PEM certificate"
		return result
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to parse certificate: %v", err)
		return result
	}

	result.CommonName = cert.Subject.CommonName
	result.ValidFrom = cert.NotBefore
	result.ValidTo = cert.NotAfter

	if len(cert.Subject.Organization) > 0 {
		result.Organization = cert.Subject.Organization[0]
	}

	// Check certificate validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		result.ErrorMessage = "certificate is not yet valid"
		return result
	}
	if now.After(cert.NotAfter) {
		result.ErrorMessage = "certificate has expired"
		return result
	}

	// Extract cloud ID from certificate (could be in Subject CN, Organization, or extension)
	cloudID := gsm.extractCloudIDFromCertificate(cert)
	if cloudID == "" {
		result.ErrorMessage = "unable to extract cloud ID from certificate"
		return result
	}
	result.CloudID = cloudID

	// Verify certificate chain against trust anchors
	trustAnchor, exists := gsm.trustAnchors[cloudID]
	if !exists {
		result.ErrorMessage = fmt.Sprintf("no trust anchor found for cloud ID: %s", cloudID)
		return result
	}

	// Verify certificate signature
	if err := cert.CheckSignatureFrom(trustAnchor); err != nil {
		// Try to find intermediate CA certificates
		if err := gsm.verifyCertificateChain(cert, trustAnchor, result); err != nil {
			result.ErrorMessage = fmt.Sprintf("certificate chain verification failed: %v", err)
			return result
		}
	}

	// Validate key usage
	if !gsm.validateKeyUsage(cert) {
		result.ErrorMessage = "certificate has invalid key usage for gateway communication"
		return result
	}

	result.Valid = true
	return result
}

// GetCertificateHash returns the SHA-256 hash of a certificate
func (gsm *GatewaySecurityManager) GetCertificateHash(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}

	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:])
}

// ValidateTunnelSecurity validates security requirements for tunnel establishment
func (gsm *GatewaySecurityManager) ValidateTunnelSecurity(tunnel *pkg.GatewayTunnel, localGateway, remoteGateway *pkg.Gateway) error {
	// Validate local gateway certificate
	if localGateway.Certificate != "" {
		if err := gsm.ValidateCertificate(localGateway.Certificate); err != nil {
			return fmt.Errorf("local gateway certificate validation failed: %w", err)
		}
	}

	// Validate remote gateway certificate
	if remoteGateway.Certificate != "" {
		if err := gsm.ValidateCertificate(remoteGateway.Certificate); err != nil {
			return fmt.Errorf("remote gateway certificate validation failed: %w", err)
		}
	}

	// Validate encryption requirements based on tunnel protocol
	switch tunnel.Protocol {
	case pkg.TunnelProtocolHTTPS:
		if tunnel.EncryptionType == "" {
			tunnel.EncryptionType = "TLS"
		}
	case pkg.TunnelProtocolMQTT:
		if tunnel.EncryptionType == "" {
			tunnel.EncryptionType = "TLS"
		}
	}

	// Generate shared secret if not provided
	if tunnel.SharedSecret == "" {
		secret, err := gsm.generateSharedSecret()
		if err != nil {
			return fmt.Errorf("failed to generate shared secret: %w", err)
		}
		tunnel.SharedSecret = secret
	}

	return nil
}

// EncryptMessage encrypts a gateway message using AES encryption with the tunnel's shared secret
func (gsm *GatewaySecurityManager) EncryptMessage(message *pkg.GatewayMessage) error {
	if !message.Encrypted {
		return nil // Message doesn't require encryption
	}

	if message.SharedSecret == "" {
		return fmt.Errorf("shared secret is required for message encryption")
	}

	gsm.logger.WithField("message_id", message.ID).Debug("Encrypting gateway message")

	// Derive encryption key from shared secret
	key := sha256.Sum256([]byte(message.SharedSecret))

	// Create AES cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create GCM mode for authenticated encryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt the payload
	ciphertext := gcm.Seal(nil, iv, message.Payload, nil)

	// Prepend IV to ciphertext and encode as base64
	encryptedData := append(iv, ciphertext...)
	message.Payload = []byte(base64.StdEncoding.EncodeToString(encryptedData))

	gsm.logger.WithField("message_id", message.ID).Debug("Message encrypted successfully")

	return nil
}

// DecryptMessage decrypts a gateway message using AES decryption with the tunnel's shared secret
func (gsm *GatewaySecurityManager) DecryptMessage(message *pkg.GatewayMessage) error {
	if !message.Encrypted {
		return nil // Message is not encrypted
	}

	if message.SharedSecret == "" {
		return fmt.Errorf("shared secret is required for message decryption")
	}

	gsm.logger.WithField("message_id", message.ID).Debug("Decrypting gateway message")

	// Decode base64 encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(string(message.Payload))
	if err != nil {
		return fmt.Errorf("failed to decode encrypted payload: %w", err)
	}

	// Extract IV and ciphertext
	if len(encryptedData) < aes.BlockSize {
		return fmt.Errorf("encrypted data is too short")
	}

	iv := encryptedData[:aes.BlockSize]
	ciphertext := encryptedData[aes.BlockSize:]

	// Derive decryption key from shared secret
	key := sha256.Sum256([]byte(message.SharedSecret))

	// Create AES cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode for authenticated decryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the payload
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt message: %w", err)
	}

	message.Payload = plaintext

	gsm.logger.WithField("message_id", message.ID).Debug("Message decrypted successfully")

	return nil
}

// SignMessage creates a digital signature for a gateway message
func (gsm *GatewaySecurityManager) SignMessage(message *pkg.GatewayMessage) error {
	if gsm.privateKey == nil {
		return fmt.Errorf("no private key available for signing")
	}

	// Create message hash for signing
	messageData := fmt.Sprintf("%s:%s:%s:%s:%s",
		message.ID,
		message.Type,
		message.SourceCloud,
		message.TargetCloud,
		string(message.Payload))

	hash := sha256.Sum256([]byte(messageData))

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, gsm.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	message.Signature = base64.StdEncoding.EncodeToString(signature)

	gsm.logger.WithField("message_id", message.ID).Debug("Message signed successfully")

	return nil
}

// VerifyMessageSignature verifies the digital signature of a gateway message
func (gsm *GatewaySecurityManager) VerifyMessageSignature(message *pkg.GatewayMessage, senderCertPEM string) error {
	if message.Signature == "" {
		return fmt.Errorf("message has no signature")
	}

	// Parse sender certificate
	block, _ := pem.Decode([]byte(senderCertPEM))
	if block == nil {
		return fmt.Errorf("failed to decode sender certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse sender certificate: %w", err)
	}

	// Extract public key
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("sender certificate does not contain RSA public key")
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(message.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode message signature: %w", err)
	}

	// Recreate message hash
	messageData := fmt.Sprintf("%s:%s:%s:%s:%s",
		message.ID,
		message.Type,
		message.SourceCloud,
		message.TargetCloud,
		string(message.Payload))

	hash := sha256.Sum256([]byte(messageData))

	// Verify signature
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	gsm.logger.WithField("message_id", message.ID).Debug("Message signature verified successfully")

	return nil
}

// AddTrustAnchor adds a new trust anchor for a cloud
func (gsm *GatewaySecurityManager) AddTrustAnchor(cloudID string, certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("failed to decode trust anchor certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse trust anchor certificate: %w", err)
	}

	// Validate that this is a CA certificate
	if !cert.IsCA {
		return fmt.Errorf("certificate is not a CA certificate")
	}

	gsm.trustAnchors[cloudID] = cert

	gsm.logger.WithFields(logrus.Fields{
		"cloud_id":    cloudID,
		"common_name": cert.Subject.CommonName,
		"valid_from":  cert.NotBefore,
		"valid_to":    cert.NotAfter,
	}).Info("Trust anchor added successfully")

	return nil
}

// RemoveTrustAnchor removes a trust anchor for a cloud
func (gsm *GatewaySecurityManager) RemoveTrustAnchor(cloudID string) error {
	if _, exists := gsm.trustAnchors[cloudID]; !exists {
		return fmt.Errorf("trust anchor for cloud %s not found", cloudID)
	}

	delete(gsm.trustAnchors, cloudID)

	gsm.logger.WithField("cloud_id", cloudID).Info("Trust anchor removed")

	return nil
}

// GetTrustAnchors returns all configured trust anchors
func (gsm *GatewaySecurityManager) GetTrustAnchors() []*TrustAnchor {
	anchors := make([]*TrustAnchor, 0, len(gsm.trustAnchors))

	for cloudID, cert := range gsm.trustAnchors {
		anchors = append(anchors, &TrustAnchor{
			CloudID:     cloudID,
			Certificate: cert,
			PublicKey:   cert.PublicKey,
			ValidFrom:   cert.NotBefore,
			ValidTo:     cert.NotAfter,
		})
	}

	return anchors
}

// GenerateGatewayCertificate generates a new certificate for gateway communication
func (gsm *GatewaySecurityManager) GenerateGatewayCertificate(cloudID, commonName string, validityPeriod time.Duration) (certPEM, keyPEM string, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{cloudID},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validityPeriod),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	certPEMBytes := pem.EncodeToMemory(certPEMBlock)

	// Encode private key to PEM
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEMBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	keyPEMBytes := pem.EncodeToMemory(keyPEMBlock)

	return string(certPEMBytes), string(keyPEMBytes), nil
}

// Private methods

func (gsm *GatewaySecurityManager) loadGatewayCertificate() error {
	// Skip loading if gateway is not enabled
	if !gsm.config.GetGateway().Enabled {
		gsm.logger.Debug("Gateway is disabled, skipping certificate loading")
		return nil
	}

	certFile := gsm.config.GetGateway().CertificateFile
	keyFile := gsm.config.GetGateway().PrivateKeyFile

	// If no certificate files are configured, generate self-signed certificate
	if certFile == "" || keyFile == "" {
		gsm.logger.Info("No gateway certificate configured, generating self-signed certificate")
		return gsm.generateSelfSignedCertificate()
	}

	// Load certificate file
	if err := gsm.loadCertificateFromFile(certFile); err != nil {
		return fmt.Errorf("failed to load certificate from %s: %w", certFile, err)
	}

	// Load private key file
	if err := gsm.loadPrivateKeyFromFile(keyFile); err != nil {
		return fmt.Errorf("failed to load private key from %s: %w", keyFile, err)
	}

	gsm.logger.WithFields(logrus.Fields{
		"certificate_file": certFile,
		"private_key_file": keyFile,
		"common_name":      gsm.certificate.Subject.CommonName,
		"valid_from":       gsm.certificate.NotBefore,
		"valid_to":         gsm.certificate.NotAfter,
	}).Info("Gateway certificate and private key loaded successfully")

	return nil
}

func (gsm *GatewaySecurityManager) loadTrustAnchors() error {
	// Skip loading if gateway is not enabled
	if !gsm.config.GetGateway().Enabled {
		gsm.logger.Debug("Gateway is disabled, skipping trust anchor loading")
		return nil
	}

	trustAnchorsLoaded := 0

	// Load trust anchors from individual certificate files
	for _, anchor := range gsm.config.GetGateway().TrustAnchors {
		if err := gsm.loadTrustAnchorFromFile(anchor.CloudID, anchor.Certificate); err != nil {
			gsm.logger.WithError(err).WithFields(logrus.Fields{
				"cloud_id":    anchor.CloudID,
				"certificate": anchor.Certificate,
			}).Error("Failed to load trust anchor")
			continue
		}
		trustAnchorsLoaded++
	}

	// Load trust anchors from trust store directory
	if gsm.config.GetGateway().TrustStore != "" {
		loaded, err := gsm.loadTrustAnchorsFromDirectory(gsm.config.GetGateway().TrustStore)
		if err != nil {
			gsm.logger.WithError(err).WithField("trust_store", gsm.config.GetGateway().TrustStore).
				Warn("Failed to load some trust anchors from trust store")
		}
		trustAnchorsLoaded += loaded
	}

	gsm.logger.WithField("trust_anchors_loaded", trustAnchorsLoaded).Info("Trust anchors loaded")

	return nil
}

func (gsm *GatewaySecurityManager) extractCloudIDFromCertificate(cert *x509.Certificate) string {
	// Try to extract cloud ID from certificate subject
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}

	// Try to extract from common name (format: gateway-<cloudid>)
	if strings.HasPrefix(cert.Subject.CommonName, "gateway-") {
		return strings.TrimPrefix(cert.Subject.CommonName, "gateway-")
	}

	// Could also check certificate extensions for custom cloud ID field
	return ""
}

func (gsm *GatewaySecurityManager) verifyCertificateChain(cert, trustAnchor *x509.Certificate, result *CertificateValidationResult) error {
	// Build certificate chain
	intermediates := x509.NewCertPool()

	// Add any known intermediate CA certificates
	for _, caCert := range gsm.caCerts {
		intermediates.AddCert(caCert)
	}

	// Create verification options
	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: intermediates,
	}
	opts.Roots.AddCert(trustAnchor)

	// Verify certificate chain
	chains, err := cert.Verify(opts)
	if err != nil {
		return err
	}

	if len(chains) > 0 {
		result.TrustChain = chains[0]
	}

	return nil
}

func (gsm *GatewaySecurityManager) validateKeyUsage(cert *x509.Certificate) bool {
	// Check that certificate has appropriate key usage for gateway communication
	hasDigitalSignature := cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
	hasKeyEncipherment := cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0

	// Check extended key usage
	hasServerAuth := false
	hasClientAuth := false

	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}

	return hasDigitalSignature && hasKeyEncipherment && hasServerAuth && hasClientAuth
}

func (gsm *GatewaySecurityManager) generateSharedSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// Helper methods for certificate loading

func (gsm *GatewaySecurityManager) loadCertificateFromFile(certFile string) error {
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Validate certificate is not expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (valid from %v)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (valid until %v)", cert.NotAfter)
	}

	gsm.certificate = cert
	return nil
}

func (gsm *GatewaySecurityManager) loadPrivateKeyFromFile(keyFile string) error {
	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM private key")
	}

	// Try to parse as PKCS#8 first, then PKCS#1
	var privateKey interface{}
	if privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		if privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	// Ensure it's an RSA private key
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not an RSA key")
	}

	// Validate key matches certificate
	if gsm.certificate != nil {
		if err := gsm.validateKeyPair(rsaKey, gsm.certificate); err != nil {
			return fmt.Errorf("private key does not match certificate: %w", err)
		}
	}

	gsm.privateKey = rsaKey
	return nil
}

func (gsm *GatewaySecurityManager) loadTrustAnchorFromFile(cloudID, certFile string) error {
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	return gsm.AddTrustAnchor(cloudID, string(certPEM))
}

func (gsm *GatewaySecurityManager) loadTrustAnchorsFromDirectory(trustStore string) (int, error) {
	files, err := ioutil.ReadDir(trustStore)
	if err != nil {
		return 0, fmt.Errorf("failed to read trust store directory: %w", err)
	}

	loaded := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Only process .crt, .pem, .cer files
		ext := strings.ToLower(filepath.Ext(file.Name()))
		if ext != ".crt" && ext != ".pem" && ext != ".cer" {
			continue
		}

		certPath := filepath.Join(trustStore, file.Name())

		// Extract cloud ID from filename (format: cloudid.crt or cloudid.pem)
		cloudID := strings.TrimSuffix(file.Name(), ext)

		if err := gsm.loadTrustAnchorFromFile(cloudID, certPath); err != nil {
			gsm.logger.WithError(err).WithFields(logrus.Fields{
				"cloud_id":         cloudID,
				"certificate_file": certPath,
			}).Warn("Failed to load trust anchor from directory")
			continue
		}

		loaded++
	}

	return loaded, nil
}

func (gsm *GatewaySecurityManager) generateSelfSignedCertificate() error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("gateway-%s", gsm.config.GetGateway().CloudID),
			Organization: []string{gsm.config.GetGateway().CloudID},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	gsm.certificate = cert
	gsm.privateKey = privateKey

	gsm.logger.WithFields(logrus.Fields{
		"common_name": cert.Subject.CommonName,
		"cloud_id":    gsm.config.GetGateway().CloudID,
		"valid_from":  cert.NotBefore,
		"valid_to":    cert.NotAfter,
	}).Info("Generated self-signed gateway certificate")

	return nil
}

func (gsm *GatewaySecurityManager) validateKeyPair(privateKey *rsa.PrivateKey, cert *x509.Certificate) error {
	// Get public key from certificate
	certPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain RSA public key")
	}

	// Compare public keys
	if privateKey.PublicKey.N.Cmp(certPublicKey.N) != 0 || privateKey.PublicKey.E != certPublicKey.E {
		return fmt.Errorf("private key does not match certificate public key")
	}

	return nil
}
