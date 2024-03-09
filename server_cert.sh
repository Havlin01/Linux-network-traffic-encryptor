#!/bin/sh


# Set the paths
SERVER_KEY="server.key"
SERVER_CSR="server.csr"
SERVER_CERT="server.crt"
CA_KEY="ca.key"
CA_CERT="ca.crt"

# Generate server private key using Dilithium-5 algorithm
openssl genpkey -algorithm dilithium5 -out "$SERVER_KEY" 

# Generate server certificate signing request (CSR)
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -subj "/CN=Server"

# Sign the CSR with the CA's private key to create the server certificate
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVER_CERT" -days 365 

echo "Server certificate signed successfully."