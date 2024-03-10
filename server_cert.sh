#!/bin/sh


# Remove any existing server key, certificate, and certificate signing request

rm -rf "server-dilithium-key.pem" "server-dilithium-csr.pem " "server-dilithium-cert.pem"

openssl genpkey -algorithm dilithium3 -out server-dilithium-key.pem
openssl req -new -key server-dilithium-key.pem -out server-dilithium-csr.pem
openssl x509 -req -in server-dilithium-csr.pem -out server-dilithium-cert.pem -CA ca-cert.pem -CAkey ca-key.pem -days 365 -CAcreateserial

echo "Server certificate signed successfully."