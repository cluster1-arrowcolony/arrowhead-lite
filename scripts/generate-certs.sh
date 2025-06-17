#!/bin/bash

# ---
# Arrowhead Lite Certificate Generation Script (Complete)
# ---
# This script creates a complete set of self-signed TLS certificates
# and JWT signing keys for a secure, local development environment.
#
# It generates all files needed for both arrowhead-lite AND the Python SDK, including:
#   1. A local Certificate Authority (CA).
#   2. A server certificate with a proper Subject Alternative Name (SAN).
#   3. A 'sysop' admin client certificate.
#   4. A PKCS#12 bundle for the CA itself (ca.p12) for use by the Python SDK.
#   5. An RSA key pair for signing and verifying JSON Web Tokens (JWTs).
#
# All generated files will be placed in the `certs/` directory.
# ---

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}--- Arrowhead Lite Complete Certificate Generation ---${NC}"
echo

# Set the target directory relative to the script's location
CERT_DIR="$(dirname "$0")/../certs"
V3_EXT_FILE="$CERT_DIR/v3.ext"

# Check for OpenSSL
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: openssl command not found. Please install OpenSSL.${NC}"
    exit 1
fi

# Clean up and create the certs directory
if [ -d "$CERT_DIR" ]; then
    echo -e "${YELLOW}Warning: Existing 'certs' directory found. This will be replaced.${NC}"
    read -p "Do you want to continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
    rm -rf "$CERT_DIR"
fi

mkdir -p "$CERT_DIR"
echo "✅ Created clean 'certs' directory."

# --- Step 1: Create the Certificate Authority (CA) ---
echo
echo -e "${BLUE}1. Creating local Certificate Authority (CA)...${NC}"
openssl genrsa -out "$CERT_DIR/ca.key" 4096
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 -out "$CERT_DIR/truststore.pem" -subj "/CN=ArrowheadLiteLocalCA"
echo "   📜 CA Public Cert: certs/truststore.pem"
echo "   🔑 CA Private Key: certs/ca.key"

# --- Step 2: Create the Server Certificate (with SAN) ---
echo
echo -e "${BLUE}2. Creating Server Certificate for arrowhead-lite...${NC}"
openssl genrsa -out "$CERT_DIR/server.key" 2048
openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" -subj "/CN=localhost"

# Create the v3.ext file for Subject Alternative Name (SAN)
cat > "$V3_EXT_FILE" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
EOF

# Sign the server CSR with the CA and include the SAN extension
openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/truststore.pem" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.pem" \
    -days 365 -sha256 \
    -extfile "$V3_EXT_FILE"
echo "   📜 Server Cert:    certs/server.pem (with SAN for 'localhost')"
echo "   🔑 Server Key:     certs/server.key"

# --- Step 3: Create the 'sysop' Admin Client Certificate ---
echo
echo -e "${BLUE}3. Creating 'sysop' Admin Client Certificate...${NC}"
openssl genrsa -out "$CERT_DIR/sysop.key" 2048
openssl req -new -key "$CERT_DIR/sysop.key" -out "$CERT_DIR/sysop.csr" -subj "/CN=sysop"
openssl x509 -req -in "$CERT_DIR/sysop.csr" -CA "$CERT_DIR/truststore.pem" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/sysop.pem" -days 365

# Prompt for a universal password
echo
echo -e "${YELLOW}Please set a password for all generated PKCS#12 files (.p12).${NC}"
echo -n "Enter password (e.g., 123456): "
read -s P12_PASSWORD
echo
# Use a default password if none is entered
if [ -z "$P12_PASSWORD" ]; then
    P12_PASSWORD="123456"
    echo "Using default password '123456'."
fi

# Create sysop PKCS#12 bundle
openssl pkcs12 -export -out "$CERT_DIR/sysop.p12" -inkey "$CERT_DIR/sysop.key" -in "$CERT_DIR/sysop.pem" -passout "pass:$P12_PASSWORD"
echo "   📦 SysOp Bundle:   certs/sysop.p12 (for SDK 'systems ls')"

# --- Step 4: Create the CA PKCS#12 Keystore for the Python SDK ---
echo
echo -e "${BLUE}4. Creating CA Keystore for Python SDK...${NC}"
openssl pkcs12 -export -out "$CERT_DIR/ca.p12" -inkey "$CERT_DIR/ca.key" -in "$CERT_DIR/truststore.pem" -name "ArrowheadLiteLocalCA" -passout "pass:$P12_PASSWORD"
echo "   📦 CA Keystore:    certs/ca.p12 (for SDK 'systems register')"

# --- Step 5: Create JWT Signing Keys ---
echo
echo -e "${BLUE}5. Creating JWT Signing Keys...${NC}"
openssl genpkey -algorithm RSA -out "$CERT_DIR/auth-private.pem" -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in "$CERT_DIR/auth-private.pem" -out "$CERT_DIR/auth-public.pem"
echo "   🔑 JWT Keys:       certs/auth-private.pem, certs/auth-public.pem"

# --- Step 6: Clean Up ---
echo
echo -e "${BLUE}6. Cleaning up intermediate files...${NC}"
rm "$CERT_DIR"/*.csr "$CERT_DIR"/*.srl "$V3_EXT_FILE"
echo "   ✅ Removed temporary files."

# --- Final Instructions ---
echo
echo -e "${GREEN}--------------------------------------------------${NC}"
echo -e "${GREEN}✅ All necessary certificates have been generated!${NC}"
echo -e "${GREEN}--------------------------------------------------${NC}"
echo
echo "Your 'certs/' directory now contains:"
echo "  - server.pem, server.key: For the arrowhead-lite server."
echo "  - truststore.pem:         For servers and clients to trust the CA."
echo "  - sysop.p12:              For the Python SDK to run management commands."
echo "  - ca.p12:                 For the Python SDK to register new systems."
echo "  - auth-*.pem:             For JWT signing and verification."
echo
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Ensure 'configs/config.yaml' has TLS enabled."
echo "2. Run './bin/arrowhead-lite' to start the server."
echo "3. Update and source your 'arrowhead-lite.env' in the Python SDK project."
echo "   (Make sure ARROWHEAD_ROOT_KEYSTORE points to 'certs/ca.p12')"
echo
