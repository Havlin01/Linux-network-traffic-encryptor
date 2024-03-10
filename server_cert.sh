#!/bin/sh


# Remove any existing server key, certificate, and certificate signing request

rm -rf "srv.key" "srv.csr" "srv.crt"

openssl genpkey -algorithm dilithium3 -out srv.key
openssl req -new -newkey dilithium3 -keyout srv.key -out srv.csr 
openssl x509 -req -in srv.csr -out srv.crt -CA ca.crt -CAkey ca.key -CAcreateserial -days 365

echo "Server certificate signed successfully."