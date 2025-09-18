# Security Documentation

## Security Overview

Arrowhead Lite implements multiple layers of security to protect IoT service mesh communications and data. This document covers security features, best practices, and compliance considerations.

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────┐
│            Layer 4: Application             │
│        (Authorization, Rate Limiting)        │
├─────────────────────────────────────────────┤
│            Layer 3: Authentication          │
│         (JWT Tokens, Certificates)          │
├─────────────────────────────────────────────┤
│            Layer 2: Transport               │
│           (TLS 1.3, mTLS, Ciphers)          │
├─────────────────────────────────────────────┤
│            Layer 1: Network                 │
│        (Firewall, VPN, Segmentation)        │
└─────────────────────────────────────────────┘
```

## Transport Security

### TLS Configuration

#### Production TLS Settings

```yaml
tls:
  enabled: true
  min_version: "TLS1.3"
  cipher_suites:
    - TLS_AES_256_GCM_SHA384
    - TLS_AES_128_GCM_SHA256
    - TLS_CHACHA20_POLY1305_SHA256
  client_auth: true
  verify_depth: 3
```

#### Certificate Requirements

- **Key Size**: Minimum 2048-bit RSA or 256-bit ECDSA
- **Signature Algorithm**: SHA-256 or stronger
- **Validity Period**: Maximum 397 days (13 months)
- **Subject Alternative Names**: Required for all certificates

### mTLS (Mutual TLS)

#### Client Certificate Authentication

```bash
# Generate client certificate
openssl req -new -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr \
  -subj "/C=US/O=Organization/CN=client-system"

# Sign with CA
openssl x509 -req -in client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 \
  -extensions v3_client
```

#### Certificate Validation Chain

1. Verify certificate is not expired
2. Check certificate chain to trusted CA
3. Validate certificate purpose (client auth)
4. Extract and verify system identity
5. Check against revocation list (if enabled)

### Certificate Management

#### Certificate Rotation

```bash
#!/bin/bash
# rotate-certificates.sh

# Generate new certificates
./generate-certs.sh --rotate

# Backup old certificates
mv certs/ certs.backup.$(date +%Y%m%d)/

# Install new certificates
mv certs.new/ certs/

# Reload without downtime
systemctl reload arrowhead-lite
```

#### Certificate Monitoring

```yaml
monitoring:
  alerts:
    - name: certificate_expiry
      condition: "days_until_expiry < 30"
      action: "email:admin@example.com"
    - name: certificate_expired
      condition: "is_expired == true"
      action: "pagerduty:critical"
```

## Authentication

### JWT Token Security

#### Token Generation

```go
// Secure token generation example
type Claims struct {
    SystemID   int64    `json:"system_id"`
    SystemName string   `json:"system_name"`
    Roles      []string `json:"roles"`
    jwt.StandardClaims
}

func GenerateToken(system *System) (string, error) {
    claims := Claims{
        SystemID:   system.ID,
        SystemName: system.Name,
        Roles:      system.Roles,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
            IssuedAt:  time.Now().Unix(),
            NotBefore: time.Now().Unix(),
            Issuer:    "arrowhead-lite",
            Subject:   system.Name,
            Id:        uuid.New().String(),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(secret))
}
```

#### Token Validation

```go
func ValidateToken(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, 
        func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method")
            }
            return []byte(secret), nil
        })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }
    
    return nil, errors.New("invalid token")
}
```

### API Key Management

#### Secure API Key Generation

```bash
# Generate secure API key
openssl rand -hex 32

# Store in environment variable
export ARROWHEAD_API_KEY=<generated-key>
```

#### API Key Rotation Policy

- Rotate keys every 90 days
- Maintain overlap period for migration
- Audit all key usage
- Revoke compromised keys immediately

## Authorization

### Role-Based Access Control (RBAC)

#### Role Definitions

```yaml
roles:
  admin:
    description: "Full system access"
    permissions:
      - "*:*"
  
  service_provider:
    description: "Can register and manage services"
    permissions:
      - "registry:create"
      - "registry:update"
      - "registry:delete"
      - "registry:read"
  
  service_consumer:
    description: "Can discover and consume services"
    permissions:
      - "registry:read"
      - "orchestration:request"
  
  monitor:
    description: "Read-only monitoring access"
    permissions:
      - "*:read"
      - "metrics:read"
      - "health:read"
```

#### Permission Enforcement

```go
func CheckPermission(user *User, resource, action string) bool {
    for _, role := range user.Roles {
        for _, permission := range role.Permissions {
            if matchPermission(permission, resource, action) {
                return true
            }
        }
    }
    return false
}
```

### Service-Level Authorization

#### Authorization Rules

```json
{
  "consumer": {
    "systemName": "sensor-reader",
    "certificate_thumbprint": "SHA256:abc123..."
  },
  "provider": {
    "systemName": "temperature-sensor",
    "serviceDefinition": "temperature"
  },
  "interfaces": ["HTTP-SECURE-JSON"],
  "constraints": {
    "time_window": "08:00-18:00",
    "rate_limit": "100/minute",
    "data_fields": ["temperature", "timestamp"]
  }
}
```

## Data Security

### Encryption at Rest

#### Database Encryption

```yaml
database:
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
    key_rotation_interval: "30d"
    key_derivation: "PBKDF2"
```

#### Sensitive Data Handling

```go
// Encrypt sensitive fields
type System struct {
    ID                 int64
    SystemName         string
    AuthenticationInfo string `encrypt:"true"`
    PrivateKey         string `encrypt:"true"`
}

// Encryption middleware
func EncryptField(data string) string {
    cipher, _ := aes.NewCipher(encryptionKey)
    gcm, _ := cipher.NewGCM()
    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)
    return base64.StdEncoding.EncodeToString(
        gcm.Seal(nonce, nonce, []byte(data), nil))
}
```

### Encryption in Transit

#### Internal Communication

```yaml
internal:
  encryption:
    enabled: true
    protocol: "TLS1.3"
    mutual_auth: true
    certificate_validation: "strict"
```

## Input Validation

### Request Validation

```go
// Input sanitization
func ValidateSystemRegistration(req *RegistrationRequest) error {
    // Validate system name
    if !regexp.MustCompile(`^[a-zA-Z0-9-._]+$`).MatchString(req.SystemName) {
        return errors.New("invalid system name format")
    }
    
    // Validate IP address
    if net.ParseIP(req.Address) == nil {
        return errors.New("invalid IP address")
    }
    
    // Validate port range
    if req.Port < 1 || req.Port > 65535 {
        return errors.New("invalid port number")
    }
    
    // Validate service URIs
    for _, service := range req.Services {
        if _, err := url.Parse(service.URI); err != nil {
            return fmt.Errorf("invalid service URI: %v", err)
        }
    }
    
    return nil
}
```

### SQL Injection Prevention

```go
// Always use parameterized queries
func GetSystem(db *sql.DB, systemName string) (*System, error) {
    // Safe: uses parameterized query
    query := "SELECT * FROM systems WHERE system_name = ?"
    row := db.QueryRow(query, systemName)
    
    // Never do this:
    // query := fmt.Sprintf("SELECT * FROM systems WHERE system_name = '%s'", systemName)
    
    var system System
    err := row.Scan(&system.ID, &system.SystemName, ...)
    return &system, err
}
```

### XSS Prevention

```go
// HTML escaping for web responses
func SanitizeOutput(data string) string {
    return html.EscapeString(data)
}

// JSON responses are automatically escaped
func RespondJSON(w http.ResponseWriter, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    json.NewEncoder(w).Encode(data)
}
```

## Security Headers

### HTTP Security Headers

```go
func SecurityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Prevent clickjacking
        w.Header().Set("X-Frame-Options", "DENY")
        
        // Prevent MIME sniffing
        w.Header().Set("X-Content-Type-Options", "nosniff")
        
        // Enable XSS protection
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        
        // Content Security Policy
        w.Header().Set("Content-Security-Policy", 
            "default-src 'self'; script-src 'self'; style-src 'self'")
        
        // Strict Transport Security
        if r.TLS != nil {
            w.Header().Set("Strict-Transport-Security", 
                "max-age=31536000; includeSubDomains")
        }
        
        // Referrer Policy
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        
        // Permissions Policy
        w.Header().Set("Permissions-Policy", 
            "geolocation=(), microphone=(), camera=()")
        
        next.ServeHTTP(w, r)
    })
}
```

## Rate Limiting

### Configuration

```yaml
rate_limiting:
  global:
    requests_per_second: 100
    burst: 200
  
  per_endpoint:
    "/api/register":
      requests_per_minute: 10
      burst: 20
    "/api/query":
      requests_per_minute: 60
      burst: 100
  
  per_client:
    default:
      requests_per_minute: 100
    trusted:
      requests_per_minute: 1000
```

### Implementation

```go
func RateLimitMiddleware(limiter *rate.Limiter) gin.HandlerFunc {
    return func(c *gin.Context) {
        if !limiter.Allow() {
            c.JSON(429, gin.H{
                "error": "rate limit exceeded",
                "retry_after": limiter.Reserve().Delay(),
            })
            c.Abort()
            return
        }
        c.Next()
    }
}
```

## Audit Logging

### Audit Event Structure

```json
{
  "timestamp": "2025-01-15T10:30:45Z",
  "event_type": "authorization.granted",
  "actor": {
    "system_id": 123,
    "system_name": "consumer-system",
    "ip_address": "192.168.1.100",
    "certificate_subject": "CN=consumer-system"
  },
  "resource": {
    "type": "service",
    "id": 456,
    "name": "temperature-sensor"
  },
  "action": "consume",
  "result": "success",
  "metadata": {
    "authorization_id": 789,
    "token_id": "abc-123"
  }
}
```

### Audit Configuration

```yaml
audit:
  enabled: true
  
  # Events to audit
  events:
    - authentication.*
    - authorization.*
    - registration.*
    - certificate.*
    - configuration.changed
    - security.violation
  
  # Storage backend
  storage:
    type: "database"  # database, file, syslog, elasticsearch
    retention: "90d"
    
  # Alerting
  alerts:
    - event: "security.violation"
      action: "email:security@example.com"
    - event: "authentication.failed"
      threshold: 5
      window: "5m"
      action: "block_ip"
```

## Vulnerability Management

### Dependency Scanning

```bash
# Go vulnerability check
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Security scanning
gosec -fmt sarif -out gosec-results.sarif ./...

# Dependency audit
nancy sleuth

# Container scanning (if using Docker)
trivy image arrowhead-lite:latest
```

### Security Updates

```yaml
# Automated dependency updates
updates:
  schedule: "weekly"
  auto_merge:
    security: true
    minor: false
    major: false
  
  notifications:
    email: "security@example.com"
    slack: "#security-alerts"
```

## Incident Response

### Security Incident Playbook

#### 1. Detection
```bash
# Monitor for suspicious activity
tail -f /var/log/arrowhead/security.log | grep -E "(failed|violation|suspicious)"

# Check active connections
netstat -antp | grep arrowhead

# Review audit logs
journalctl -u arrowhead-lite --since "1 hour ago" | grep -i error
```

#### 2. Containment
```bash
# Block suspicious IP
iptables -A INPUT -s <suspicious-ip> -j DROP

# Revoke compromised certificates
./arrowhead-lite revoke-cert --thumbprint <cert-thumbprint>

# Disable affected service
./arrowhead-lite disable-service --name <service-name>
```

#### 3. Eradication
```bash
# Rotate all secrets
./rotate-secrets.sh

# Update and patch
git pull
make build
systemctl restart arrowhead-lite

# Clear compromised sessions
./arrowhead-lite clear-sessions --all
```

#### 4. Recovery
```bash
# Restore from backup if needed
./restore-backup.sh

# Re-enable services
./arrowhead-lite enable-service --name <service-name>

# Verify system integrity
./arrowhead-lite verify-integrity
```

## Compliance

### Standards Compliance

- **ISO 27001**: Information Security Management
- **IEC 62443**: Industrial Security Standards
- **NIST Cybersecurity Framework**: Security Controls
- **GDPR**: Data Protection (for EU deployments)
- **SOC 2**: Service Organization Controls

### Security Checklist

#### Pre-Deployment
- [ ] Generate strong certificates (2048-bit minimum)
- [ ] Configure TLS 1.3 only
- [ ] Enable mTLS for all connections
- [ ] Set up firewall rules
- [ ] Configure rate limiting
- [ ] Enable audit logging
- [ ] Set up monitoring alerts
- [ ] Review and harden configuration
- [ ] Run security scan
- [ ] Document security procedures

#### Post-Deployment
- [ ] Regular security updates
- [ ] Certificate rotation schedule
- [ ] Audit log review
- [ ] Penetration testing
- [ ] Vulnerability scanning
- [ ] Incident response drills
- [ ] Security training
- [ ] Access review
- [ ] Backup verification
- [ ] Compliance audit

## Security Best Practices

### Development Security

1. **Secure Coding**
   - Input validation on all endpoints
   - Output encoding for all responses
   - Parameterized database queries
   - Secure random number generation
   - No hardcoded secrets

2. **Code Review**
   - Security-focused code reviews
   - Automated security scanning
   - Dependency vulnerability checks
   - Static analysis tools
   - Dynamic security testing

3. **Testing**
   - Security unit tests
   - Integration security tests
   - Penetration testing
   - Fuzzing critical inputs
   - Load testing with security scenarios

### Operational Security

1. **Access Control**
   - Principle of least privilege
   - Regular access reviews
   - Multi-factor authentication for admin
   - Session timeout configuration
   - Account lockout policies

2. **Monitoring**
   - Real-time security alerts
   - Anomaly detection
   - Log aggregation and analysis
   - Security metrics dashboard
   - Incident tracking

3. **Maintenance**
   - Regular security updates
   - Patch management process
   - Configuration management
   - Change control procedures
   - Disaster recovery planning

## Security Tools

### Recommended Tools

1. **Scanning Tools**
   - `gosec`: Go security checker
   - `nancy`: Vulnerability scanner
   - `trivy`: Container scanner
   - `OWASP ZAP`: Web security scanner

2. **Monitoring Tools**
   - `fail2ban`: Intrusion prevention
   - `osquery`: System monitoring
   - `auditd`: System auditing
   - `prometheus`: Metrics collection

3. **Analysis Tools**
   - `wireshark`: Network analysis
   - `tcpdump`: Packet capture
   - `openssl`: Certificate analysis
   - `nmap`: Network discovery

### Security Scripts

#### Certificate Validation
```bash
#!/bin/bash
# validate-cert.sh

CERT_FILE=$1
CA_FILE=$2

# Check certificate validity
openssl x509 -in $CERT_FILE -text -noout

# Verify against CA
openssl verify -CAfile $CA_FILE $CERT_FILE

# Check expiration
openssl x509 -enddate -noout -in $CERT_FILE
```

#### Security Audit
```bash
#!/bin/bash
# security-audit.sh

echo "Running security audit..."

# Check for weak ciphers
nmap --script ssl-enum-ciphers -p 8443 localhost

# Test rate limiting
for i in {1..200}; do
  curl -s -o /dev/null -w "%{http_code}\n" https://localhost:8443/health
done | grep -c 429

# Review permissions
find /opt/arrowhead -type f -perm /o+w -ls

# Check for exposed ports
netstat -tulnp | grep LISTEN
```

## Security Contact

For security issues, please contact:
- Email: security@arrowhead-lite.org
- PGP Key: [public key fingerprint]
- Security Advisory: https://github.com/your-org/arrowhead-lite/security/advisories

Report security vulnerabilities privately. Do not open public issues for security problems.