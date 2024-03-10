#!/bin/sh


rm -rf "cli.key" "cli.csr" "cli.crt"

openssl genpkey -algorithm dilithium3 -out cli.key
openssl req -new -newkey dilithium3 -keyout cli.key -out cli.csr 
openssl x509 -req -in cli.csr -out cli.crt -CA ca.crt -CAkey ca.key -CAcreateserial -days 365

echo "Client certificate signed successfully."