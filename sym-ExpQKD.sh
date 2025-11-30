#!/bin/sh
CURRENTDIR=$(dirname $0)

# The C++ code calls this script like: ./sym-ExpQKD 'client 1.2.3.4'
# So we need to parse the arguments from the first parameter ($1)
MODE=$(echo $1 | cut -d' ' -f1)
KMSM_IP=$(echo $1 | cut -d' ' -f2)

if [ "$MODE" = "'client'" ] || [ "$MODE" = "client" ]
then
Rep=$(curl http://$KMSM_IP/key/)
Key=$(echo $Rep | jq '.keys[0].key' | cut -d '"' -f 2)
KeyIDSlave=$(echo $Rep | jq '.keys[0].key_ID' | cut -d '"' -f 2)
echo -n $Key | base64 -d | hexdump -v -e '/1 "%02x" ' > key
echo $KeyIDSlave > keyID
fi

if [ "$MODE" = "'server'" ] || [ "$MODE" = "server" ]
then
KeyIDSlave=$(cat keyID)

Rep=$(curl -X POST -d "keyID=$KeyIDSlave" http://$KMSM_IP/ID/)
Key=$(echo $Rep | jq '.keys[0].key' | cut -d '"' -f 2)
KeyIDSlave=$(echo $Rep | jq '.keys[0].key_ID' | cut -d '"' -f 2)
echo -n $Key | base64 -d | hexdump -v -e '/1 "%02x" ' > key
fi
