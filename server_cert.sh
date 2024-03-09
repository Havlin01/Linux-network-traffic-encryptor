#!/bin/sh


# Set the paths
SERVER_KEY="server_key.pem"
SERVER_CSR="server_csr.pem"
SERVER_CERT="server_cert.pem"
CA_KEY="ca_key.pem"
CA_CERT="ca_cert.pem"

rm -rf "$SERVER_KEY" "$SERVER_CSR" "$SERVER_CERT"

# Generate server private key using Dilithium-5 algorithm
openssl genpkey -algorithm dilithium5 -out "$SERVER_KEY"

# Generate server certificate signing request (CSR)
openssl req -new -sha256 -key "$SERVER_KEY" -out "$SERVER_CSR"

# Sign the CSR with the CA's private key to create the server certificate
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVER_CERT" -days 365

echo "Server certificate signed successfully."