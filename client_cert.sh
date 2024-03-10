#!/bin/sh


rm -rf "client-dilithium-key.pem" "client-dilithium-csr.pem " "client-dilithium-cert.pem"

openssl genpkey -algorithm dilithium3 -out client-dilithium-key.pem
openssl req -new -key client-dilithium-key.pem -out client-dilithium-csr.pem
openssl x509 -req -in client-dilithium-csr.pem -out client-dilithium-cert.pem -CA ca-cert.pem -CAkey ca-key.pem -days 365 -CAcreateserial


echo "Client certificate signed successfully."