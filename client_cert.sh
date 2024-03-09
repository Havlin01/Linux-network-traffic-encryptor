#!/bin/sh


# Set the paths
CLIENT_KEY="client.key"
CLIENT_CSR="client.csr"
CLIENT_CERT="client.crt"
CA_KEY="ca.key"
CA_CERT="ca.crt"

# Generate client private key using Dilithium-5 algorithm
openssl genpkey -algorithm dilithium5 -out "$CLIENT_KEY"

# Generate client certificate signing request (CSR)
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -subj "/CN=Client"

# Sign the CSR with the CA's private key to create the server certificate
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$CLIENT_CERT" -days 365

echo "Client certificate signed successfully."