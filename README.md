# Linux network traffic encryptor

## Overview 
This repository contains trial implementation of IPv4 network traffic encryption using quantum resistant algorithms.
This encryptor is meant to be used for creation of encryption gateways.

Usage of encryptor for other than testing purposes is currently highly discouraged.

Example application:

![schema](https://github.com/gabsssq/Linux-network-traffic-encryptor/assets/85123006/f8c1ad3a-0396-4b6b-bf97-12bd5adbb919)

## Modes of operation
Encryptor can run in two modes, depending on the infrastructure. First mode is without QKD servers (or simulators). Second is with QKD servers.
Mode of operation is selected by number of arguments entered when starting the encryptor (see Usage).

## Encryption
Traffic is encrypted on virtual interface using algorithm AES-256 GCM (Used implementation: https://www.cryptopp.com/release870.html).
Key for AES is derived from QKD, ECDH and PQC keys.

QKD key can be obtained from REST API of real QKD system or attached simulator.
PQC key is established using algorithm Kyber-512 (Used implementation: https://github.com/itzmeanjan/kyber/tree/master).
ECDH key is established using NIST P-521 curve. (Curve characteristics available at: https://neuromancer.sk/std/nist/P-521)

Encrypted/unencrypted traffic is distinguished by UDP port - encrypted traffic is sent to port 62 000.
Network traffic is encrypted on packet-by-packet basis in tunnel mode - this means, that every packet is expanded by 60 bytes (16 B nonce, 16 B MAC tag, 20 B new IPv4 address, 8 B UDP header).

## Encrypted packet structure
![encrpacketstructure](https://github.com/gabsssq/Linux-network-traffic-encryptor/assets/85123006/90284fa1-a6f5-4fd8-8721-23079a0f3c03)

## Rekey
Encryptor performs rekey every 1 hour. Encryptor obtains new QKD key (if available), PQC key and ECDH key. Then derives new hybrid key.
Rekeying process can be seen below:
![rekey](https://github.com/gabsssq/Linux-network-traffic-encryptor/assets/85123006/9e6fb0b2-9698-41ab-8a97-90681583875b)

Encryptor uses TCP port 61 000 for keyID exchange. Due to key change some packets fail integrity check.

## Certificate authentication
Encryptor can authenticate the connecting gateways using certificates. You can use the scripts included in project to generate one.
The certificates must be with .crt extension. For proper functioning, obtaining of certificate of certification authority and certificate of the destination gateway is needed. 
The authentication take place automatically on start of encryptor.

## Pre-requisites
To be able to run the encryptor, libssl-dev and ca-certificates needs to be installed. If you run in the problems with certificate authentication,
maybe adding the CA certificate into the truststore can solve the issue.
```bash
sudo cp [certificatename].crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

## Encryptor installation
Installation script install.sh can be used for installation on Debian and Debian-based Linux distributions.

```bash
git clone https://github.com/gabsssq/Linux-network-traffic-encryptor.git
cd Linux-network-traffic-encryptor 
chmod +x install.sh
./install.sh [IP address of other encryption gateway network]
```

## QKD simulator installation
```bash
git clone https://github.com/gabsssq/Linux-network-traffic-encryptor.git
cd Linux-network-traffic-encryptor 
chmod +x install_QKD.sh
./install_QKD.sh
```

## Usage
### Gateways:
Encryptor is divided into 2 parts - server and client.
##### 1st Gateway (server):
```bash
./encryptor_server [local IP address of QKD system] (optional)
```

##### 2nd Gateway (client):
```bash
./encryptor_client [local IP address of QKD system] [IP address of server gateway] (optional)
```

### Endpoints:
As a result of packet expansion due to traffic encryption there is high probability, that final packet size will be higher than network MTU.
Because of this reason must be MTU on endpoints lowered by 60 bytes.

```bash
ip link set [interface] mtu [MTU value]
```

MTU value should be typically lowered to 1440 bytes, considering most networks have MTU of 1500 bytes.

## Testing
For testing purposes, we created virtual network consisting of 2 gateways and 2 endpoints using 8 thread processor. Network topology can be seen below.

![DP-topologie drawio](https://github.com/gabsssq/Linux-network-traffic-encryptor/assets/85123006/397e2725-3582-4843-90b2-57dc2c2b38fa)

Endpoints were used to simulate QKD system and were given 1 thread each. Gateways were given 2 threads each.

## Performance
#### Methodology:
Goal of the measurement was to find out average transmission speed, using file transfer.
Selected file sizes were 1 MB, 500 MB, 1 GB, 5 GB. Every file was transfered 15 times.
Measurement was divided into 3 parts - no encryption, encryption with rekeying, encryption without rekeying.


#### Results:
Encryption | 1 MB [mbps] | 500 MB [mbps] | 1 GB [mbps] | 5 GB [mbps]
--- | --- | --- | --- | ---
No encryption | 435,4 | 499,8 | 476 | 458,6
Rekeying | 162,7 | 142,6 | 140,3 | 140,6
No rekeying | 162,7 | 144 | 145,3 | 145,8

Whole measurement was performed on processor Intel Core i7 1065G7 Ice Lake.

Setup example: 

https://github.com/gabsssq/Linux-network-traffic-encryptor/assets/85123006/8101648c-dab6-4712-9bb0-a30a66ef8830


