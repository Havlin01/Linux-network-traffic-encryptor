#!/bin/sh

OPENSSL_INC_PATH="/usr/local/include"
OPENSSL_LIB_PATH="/usr/local/lib64"

# Add support for local liboqs (built in workspace)
LIBOQS_INC_PATH="./liboqs/include"
LIBOQS_LIB_PATH="./liboqs/build/lib"

Help()
{
   echo "Usage: ./install.sh [Other gateway network]"
   echo "Network format: x.x.x.x/y"
   echo
}

if [ $# -lt 1 ] || [ $1 = "-help" ] || [ $1 = "-h" ]
then
Help
exit 1
fi

sudo apt update
# Install dependencies
sudo apt install -y libboost-all-dev
cat requirements.txt | sudo xargs apt install -y

# Add routing information
Route_IP=$1

# Create TUN interface
#delete the tun0 interface if it already exists
sudo ip link delete tun0
sudo ip tuntap add name tun0 mode tun
sudo ip link set tun0 up
sudo ip addr add 192.168.1.1 peer 192.168.1.2 dev tun0

echo "1" | sudo tee /proc/sys/net/ipv4/ip_forward
sudo ip route add $Route_IP via 192.168.1.2
chmod +x sym-ExpQKD
g++ -std=c++20 -Wall -O3 -march=native -I"$OPENSSL_INC_PATH" -I"$LIBOQS_INC_PATH" -o encryptor_server encryptor_server.cpp -L"$OPENSSL_LIB_PATH" -L"$LIBOQS_LIB_PATH" -Wl,-rpath,"$OPENSSL_LIB_PATH" -Wl,-rpath,"$LIBOQS_LIB_PATH" -lssl -lcrypto -loqs -pthread
g++ -std=c++20 -Wall -O3 -march=native -I"$OPENSSL_INC_PATH" -I"$LIBOQS_INC_PATH" -o encryptor_client encryptor_client.cpp -L"$OPENSSL_LIB_PATH" -L"$LIBOQS_LIB_PATH" -Wl,-rpath,"$OPENSSL_LIB_PATH" -Wl,-rpath,"$LIBOQS_LIB_PATH" -lssl -lcrypto -loqs -pthread
touch key
touch keyID
echo
echo "Installation complete."
echo "You can now run the executables directly."
echo "Example for server: ./encryptor_server"
echo "Example for client: ./encryptor_client <server_ip>"
