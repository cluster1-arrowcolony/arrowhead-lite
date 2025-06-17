#!/bin/bash

# ---
# Arrowhead Lite Certificate Generation Script
# ---
# This script creates a complete set of self-signed TLS certificates
# and JWT signing keys for a secure, local development environment.
#
# It generates:
#   1. A local Certificate Authority (CA).
#   2. A server certificate signed by the CA (for the Go server).
#   3. A 'sysop' admin client certificate signed by the CA (for the Python SDK).
#   4. An RSA key pair for signing and verifying JSON Web Tokens (JWTs).
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

echo -e "${BLUE}--- Arrowhead Lite Certificate Generation ---${NC}"
echo

# Set the target directory relative to the script's location
CERT_DIR="$(dirname "$0")/../certs"

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
echo "   🔑 CA Key:         certs/ca.key"
echo "   📜 CA Certificate: certs/truststore.pem (This is your truststore)"

# --- Step 2: Create the Server Certificate ---
echo
echo -e "${BLUE}2. Creating Server Certificate (for arrowhead-lite)...${NC}"
openssl genrsa -out "$CERT_DIR/server.key" 2048
openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" -subj "/CN=localhost"
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/truststore.pem" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/server.pem" -days 365
echo "   🔑 Server Key:      certs/server.key"
echo "   📜 Server Cert:     certs/server.pem"

# --- Step 3: Create the 'sysop' Admin Client Certificate ---
echo
echo -e "${BLUE}3. Creating 'sysop' Admin Client Certificate (for Python SDK)...${NC}"
openssl genrsa -out "$CERT_DIR/sysop.key" 2048
openssl req -new -key "$CERT_DIR/sysop.key" -out "$CERT_DIR/sysop.csr" -subj "/CN=sysop"
openssl x509 -req -in "$CERT_DIR/sysop.csr" -CA "$CERT_DIR/truststore.pem" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/sysop.pem" -days 365

# Ask for the .p12 password
echo -n "   Please enter a password for the sysop.p12 file (e.g., 123456): "
read -s P12_PASSWORD
echo

openssl pkcs12 -export -out "$CERT_DIR/sysop.p12" -inkey "$CERT_DIR/sysop.key" -in "$CERT_DIR/sysop.pem" -passout "pass:$P12_PASSWORD"
echo "   🔑 Client Key:      certs/sysop.key"
echo "   📜 Client Cert:     certs/sysop.pem"
echo "   📦 Client Bundle:   certs/sysop.p12 (Password: '$P12_PASSWORD')"

# --- Step 4: Create JWT Signing Keys (Optional but Recommended) ---
echo
echo -e "${BLUE}4. Creating JWT Signing Keys...${NC}"
openssl genpkey -algorithm RSA -out "$CERT_DIR/auth-private.pem" -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in "$CERT_DIR/auth-private.pem" -out "$CERT_DIR/auth-public.pem"
echo "   🔑 JWT Private Key: certs/auth-private.pem"
echo "   📜 JWT Public Key:  certs/auth-public.pem"

# --- Step 5: Clean Up ---
echo
echo -e "${BLUE}5. Cleaning up intermediate files...${NC}"
rm "$CERT_DIR"/*.csr "$CERT_DIR"/*.srl
echo "   ✅ Removed temporary .csr and .srl files."

# --- Final Instructions ---
echo
echo -e "${GREEN}--------------------------------------------------${NC}"
echo -e "${GREEN}✅ Certificate generation complete!${NC}"
echo -e "${GREEN}--------------------------------------------------${NC}"
echo
echo "Your 'certs/' directory now contains all necessary files."
echo
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. **Configure arrowhead-lite:**"
echo "   Update 'configs/config.yaml' to enable TLS and configure JWT keys:"
echo
echo -e "${BLUE}   server:
     tls:
       enabled: true
       cert_file: \"certs/server.pem\"
       key_file: \"certs/server.key\"
       truststore_file: \"certs/truststore.pem\"
   auth:
     private_key_file: \"certs/auth-private.pem\"
     public_key_file: \"certs/auth-public.pem\"${NC}"
echo
echo "2. **Run arrowhead-lite:**"
echo "   ./bin/arrowhead-lite"
echo
echo "3. **Configure the Python SDK:**"
echo "   Create or update your 'arrowhead.env' file with these absolute paths:"
echo -e "${BLUE}   export ARROWHEAD_TLS=\"true\"
   export ARROWHEAD_SYSOPS_KEYSTORE=\"$(pwd)/certs/sysop.p12\"
   export ARROWHEAD_KEYSTORE_PASSWORD=\"$P12_PASSWORD\"
   export ARROWHEAD_TRUSTSTORE=\"$(pwd)/certs/truststore.pem\"
   export ARROWHEAD_SERVICEREGISTRY_HOST=\"localhost\"
   # ... (and other hosts) ... ${NC}"
echo
