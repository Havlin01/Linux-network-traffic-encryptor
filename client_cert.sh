#!/bin/sh


# Set the paths
CLIENT_KEY="server_key.pem"
CLIENT_CSR="server_csr.pem"
CLIENT_CERT="server_cert.pem"
CA_KEY="ca.key"
CA_CERT="ca.crt"

# Generate server private key using Dilithium-5 algorithm
openssl genpkey -algorithm dilithium5 -out "$CLIENT_KEY"

# Generate server certificate signing request (CSR)
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR"

# Sign the CSR with the CA's private key to create the server certificate
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$CLIENT_CERT" -days 365

echo "Server certificate signed successfully."