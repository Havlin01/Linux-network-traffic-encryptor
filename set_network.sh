#!/bin/sh

#prompt user for input of network
echo "Enter the network you want to connect to in the format x.x.x.x/y"
read Route_IP

#prompt user for input of gateway
echo "Enter the gateway you want to connect to in the format x.x.x.x"
read Gateway_IP

sudo ip route add $Route_IP via $Gateway_IP

echo "Network set successfully"