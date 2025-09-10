#!/bin/bash

# ---
# Arrowhead Lite System Certificate Generation Script
# ---
# This script creates a standard TLS certificate for a new Arrowhead System.
# It must be run *after* the main 'scripts/generate-certs.sh' script,
# as it uses the Certificate Authority (CA) created by it.
#
# Usage:
#   ./scripts/generate-system-cert.sh <system-name>
#
# Example:
#   ./scripts/generate-system-cert.sh my-system
#
# This will create:
#   - certs/my-system.key (Private Key)
#   - certs/my-system.pem (Public Certificate)
# ---

set -e

# --- Configuration and Colors ---
SYSTEM_NAME=$1
SCRIPT_DIR="$(dirname "$0")"
CERT_DIR="$SCRIPT_DIR/../certs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- 1. Input Validation ---
if [ -z "$SYSTEM_NAME" ]; then
    echo -e "${RED}Error: No system name provided.${NC}"
    echo "Usage: $0 <system-name>"
    exit 1
fi

if ! [[ "$SYSTEM_NAME" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    echo -e "${RED}Error: Invalid system name.${NC} Please use only alphanumeric characters, dots, underscores, or hyphens."
    exit 1
fi

echo -e "${BLUE}--- Generating Certificate for System: ${YELLOW}$SYSTEM_NAME${BLUE} ---${NC}"

# --- 2. Prerequisite Checks ---
CA_P12="$CERT_DIR/ca.p12"
TRUSTSTORE="$CERT_DIR/truststore.pem"
OUTPUT_KEY="$CERT_DIR/$SYSTEM_NAME.key"
OUTPUT_PEM="$CERT_DIR/$SYSTEM_NAME.pem"

if [ ! -f "$CA_P12" ] || [ ! -f "$TRUSTSTORE" ]; then
    echo -e "${RED}Error: CA files not found.${NC}"
    echo "Please run './scripts/generate-certs.sh' first to create the Certificate Authority."
    exit 1
fi

if [ -f "$OUTPUT_KEY" ] || [ -f "$OUTPUT_PEM" ]; then
    echo -e "${YELLOW}Warning: Certificate files for '$SYSTEM_NAME' already exist.${NC}"
    read -p "Do you want to overwrite them? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# --- 3. Certificate Generation ---
TEMP_CA_KEY="$CERT_DIR/ca.key.tmp"
TEMP_CSR="$CERT_DIR/$SYSTEM_NAME.csr"

# Cleanup function to remove temporary files
cleanup() {
  rm -f "$TEMP_CA_KEY" "$TEMP_CSR" "$CERT_DIR/truststore.srl"
}
trap cleanup EXIT

echo "1. Extracting CA private key..."
echo -e "   -> Enter password for ${YELLOW}ca.p12${NC}. Default is ${YELLOW}123456${NC}."
echo -e "   -> Press ${YELLOW}[Enter]${NC} twice for the PEM pass phrase (to set no password)."
openssl pkcs12 -in "$CA_P12" -nocerts -out "$TEMP_CA_KEY"

echo "2. Generating new private key for '$SYSTEM_NAME'..."
openssl genrsa -out "$OUTPUT_KEY" 2048 > /dev/null 2>&1
echo "   ✅ Private key created: ${GREEN}${OUTPUT_KEY}${NC}"

echo "3. Creating Certificate Signing Request (CSR)..."
# The Common Name (CN) is critical and MUST match the system name.
openssl req -new -key "$OUTPUT_KEY" -out "$TEMP_CSR" -subj "/CN=$SYSTEM_NAME"
echo "   ✅ CSR created for CN=${GREEN}$SYSTEM_NAME${NC}"

echo "4. Signing the certificate with the local CA..."
openssl x509 -req -in "$TEMP_CSR" -CA "$TRUSTSTORE" -CAkey "$TEMP_CA_KEY" -CAcreateserial -out "$OUTPUT_PEM" -days 365
echo "   ✅ Certificate created: ${GREEN}${OUTPUT_PEM}${NC}"

# --- 4. Final Instructions ---
echo
echo -e "${GREEN}--------------------------------------------------${NC}"
echo -e "${GREEN}✅ Certificate for system '${SYSTEM_NAME}' generated successfully!${NC}"
echo -e "${GREEN}--------------------------------------------------${NC}"
echo "You can now use these files to authenticate as this system:"
echo -e "  ${YELLOW}--cert certs/${SYSTEM_NAME}.pem --key certs/${SYSTEM_NAME}.key${NC}"
echo
echo "Example usage to register this system:"
echo -e "${BLUE}curl -X POST https://localhost:8443/serviceregistry/mgmt/systems \\
  --cacert ${TRUSTSTORE} \\
  --cert ${OUTPUT_PEM} \\
  --key ${OUTPUT_KEY} \\
  -H \"Content-Type: application/json\" \\
  -d '{
    \"systemName\": \"${SYSTEM_NAME}\",
    \"address\": \"localhost\",
    \"port\": 8080
  }'${NC}"
