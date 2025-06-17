package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

// CertificateAuthority handles certificate signing for new systems
type CertificateAuthority struct {
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	logger    *logrus.Logger
	password  string
}

// NewCertificateAuthority creates a new CA instance
func NewCertificateAuthority(caCertPath, caKeyPath, password string, logger *logrus.Logger) (*CertificateAuthority, error) {
	// For now, we'll create a self-signed CA certificate if none exists
	// In production, this would load an existing CA certificate and key
	
	caCert, caKey, err := generateSelfSignedCA()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA certificate: %w", err)
	}

	return &CertificateAuthority{
		caCert:   caCert,
		caKey:    caKey,
		logger:   logger,
		password: password,
	}, nil
}

// SignSystemCertificate signs a certificate for a new system
func (ca *CertificateAuthority) SignSystemCertificate(systemName, address string, port int) ([]byte, error) {
	ca.logger.WithFields(logrus.Fields{
		"system_name": systemName,
		"address":     address,
		"port":        port,
	}).Info("Signing certificate for system")

	// Generate private key for the system
	systemKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate system private key: %w", err)
	}

	// Create certificate template for the system
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:   systemName,
			Organization: []string{"Arrowhead Framework"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{address, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP(address)},
	}

	// Sign the certificate with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.caCert, &systemKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// For now, return the certificate in PEM format
	// TODO: Implement proper PKCS#12 encoding with a different library
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	ca.logger.WithField("system_name", systemName).Info("Certificate signed successfully")
	return certPEM, nil
}

// GetCACertificatePEM returns the CA certificate in PEM format for truststore
func (ca *CertificateAuthority) GetCACertificatePEM() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.caCert.Raw,
	}), nil
}

// generateSelfSignedCA creates a self-signed CA certificate and key
func generateSelfSignedCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create CA certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:    "Arrowhead Lite CA",
			Organization:  []string{"Arrowhead Framework"},
			Country:       []string{"SE"},
			Province:      []string{""},
			Locality:      []string{"Stockholm"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	// Self-sign the CA certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the certificate
	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return caCert, caKey, nil
}