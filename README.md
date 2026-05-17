# Linux network traffic encryptor

## Overview 
This repository contains a trial implementation of IPv4 network traffic encryption using quantum-resistant algorithms.
This encryptor is meant to be used for the creation of encryption gateways that protect traffic between two network segments.

Usage of the encryptor for other than testing purposes is currently highly discouraged.

Example application:

![schema](https://github.com/gabsssq/Linux-network-traffic-encryptor/assets/85123006/f8c1ad3a-0396-4b6b-bf97-12bd5adbb919)

## Modes of operation
The encryptor can run in two modes depending on the infrastructure. The first mode operates without QKD servers or simulators, relying solely on the post-quantum and classical key exchange components. The second mode integrates with a QKD system or simulator, incorporating a quantum-derived key into the hybrid key derivation process.

The mode of operation is determined by the number of arguments provided when starting the encryptor. When the QKD IP address argument is omitted, the encryptor runs in pure post-quantum mode. When it is supplied, the encryptor contacts the QKD system during every key establishment and rekey event.

At startup, both the server and the client prompt the operator to select a post-quantum algorithm interactively. The available choices are ML-KEM-768 (formerly known as Kyber768, now standardised as FIPS 203) and HQC-256. Both sides of the tunnel must select the same algorithm for a session to be established successfully.

## Encryption
Traffic is encrypted on a virtual TUN interface using the algorithm AES-256-GCM. The implementation relies entirely on the OpenSSL EVP API for symmetric encryption, key derivation, and hashing operations.

The session key material used by AES-256-GCM is derived from a combination of post-quantum cryptography, elliptic-curve Diffie-Hellman, and optionally a QKD key. This three-component hybrid construction is designed so that a compromise of any single component alone is insufficient to break the confidentiality of the session.

The post-quantum key exchange uses either ML-KEM-768 or HQC-256. ML-KEM-768 is provided natively by OpenSSL, while HQC-256 is provided through the oqs-provider backed by the liboqs library. The ECDH component uses the NIST P-521 elliptic curve, also implemented through the OpenSSL EVP API. When QKD is enabled, the key is fetched from the local QKD system using a helper binary, and the key identifier is exchanged over the existing TCP control channel.

Encrypted traffic is distinguished from unencrypted traffic by using a dedicated UDP data channel. The server allocates an ephemeral UDP port for each connected client and communicates that port number over the TCP control channel during session setup. The client then sends all encrypted data to that port. Traffic flows in both directions over this dedicated UDP socket.

Network traffic is encrypted and decrypted on a per-packet basis. Each packet read from the TUN device is encrypted in-place before transmission and decrypted in-place upon reception. The TUN device is opened in the IFF_NO_PI mode, meaning no protocol information header is prepended to packets by the kernel.

## Encrypted packet structure
![encrpacketstructure](https://github.com/gabsssq/Linux-network-traffic-encryptor/assets/85123006/90284fa1-a6f5-4fd8-8721-23079a0f3c03)

Each transmitted UDP datagram contains, in order, a 12-byte randomly generated AES-GCM initialisation vector, the ciphertext of the original IP packet, and a 16-byte AES-GCM authentication tag. The outer UDP and IP headers added by the operating system's network stack contribute an additional 28 bytes of overhead, bringing the total per-packet expansion to approximately 56 bytes. Endpoints must therefore reduce their MTU by at least this amount to avoid fragmentation.

## Rekey
The encryptor performs a rekey every hour. The client side maintains a background timer thread that fires after one hour of operation and signals the main connection loop to initiate a rekey. When the timer fires, the client sends a REKEY_CLIENT_INITIATED message to the server over the TCP control channel, then immediately performs a fresh hybrid key exchange using the same algorithm selection that was made at startup.

Rekey can also be initiated by the server, in which case the server sends a REKEY_SERVER_INITIATED message to the client and waits for the client to proceed through the key exchange protocol.

During a rekey event, the encrypt and decrypt I/O threads are paused by acquiring an exclusive lock on the shared key material mutex. New key material is derived and atomically swapped into the active keys before the I/O threads are resumed. This design ensures that no packets are encrypted or decrypted with a partially updated key during the transition.

The TCP control channel operates on port 61000. Due to the key change, some packets in flight at the moment of key rotation may fail the AES-GCM integrity check and will be silently dropped.

## Key derivation
The hybrid key derivation procedure works as follows. The server generates a 64-byte cryptographically random salt and transmits it to the client over the framed TCP channel before any key exchange material is sent. Both sides then independently compute the same session key from the shared secrets.

For the two-component mode without QKD, each component secret is first fed through HMAC-SHA512 keyed with the salt to produce an intermediate key, and also through SHA3-512 combined with additional binding context such as the post-quantum ciphertext or the ordered concatenation of both ECDH public keys and the ECDH shared secret. The resulting digests are then combined using HMAC-SHA512 with the component-specific intermediates. The two component outputs are XOR-combined into a hybrid key, which is then hashed through SHA3-512 to produce the final 64-byte session key material. The first 32 bytes are used as the encryption key and the second 32 bytes as the decryption key.

When QKD is enabled, a third component is derived from the QKD key and a SHAKE-128 expansion of the key identifier, following the same pattern of HMAC-SHA512 and SHA3-512 processing. All three component outputs are XOR-combined before the final SHA3-512 digest step. All intermediate key material is securely erased from memory using OPENSSL_cleanse after the session key is extracted.

## Certificate authentication
The repository contains certificate generation scripts and certificate files. The constants referencing certificate file names are defined in the source code, but active TLS-based authentication on the TCP control channel is not used in the current implementation. The TLS handshake and certificate validation code present in earlier revisions has been replaced by the hybrid cryptographic key exchange described above.

## Pre-requisites
To compile and run the encryptor, the following dependencies must be present on the system.

OpenSSL version 3.x or later is required and must be installed with its development headers. The oqs-provider for OpenSSL must be compiled and installed, as it provides the HQC-256 algorithm. The liboqs library must also be present, as oqs-provider depends on it. Boost.ASIO is required for asynchronous network I/O. The packages libssl-dev and ca-certificates should be installed on Debian-based systems.

```bash
sudo apt install libssl-dev ca-certificates libboost-dev
```

The oqs-provider and liboqs repositories are included as subdirectories in this repository and must be built separately according to their respective build instructions. If the oqs-provider is not installed or cannot be loaded at startup, the HQC-256 algorithm will be unavailable and a warning will be printed, but ML-KEM-768 will continue to function using the built-in OpenSSL provider.

## Encryptor installation
The installation script install.sh can be used for installation on Debian and Debian-based Linux distributions.

```bash
git clone https://github.com/Havlin01/Linux-network-traffic-encryptor.git
cd Linux-network-traffic-encryptor 
chmod +x install.sh
./install.sh [IP address of other encryption gateway network]
```

## QKD simulator installation
```bash
git clone https://github.com/Havlin01/Linux-network-traffic-encryptor.git
cd Linux-network-traffic-encryptor 
chmod +x install_QKD.sh
./install_QKD.sh
```

## Usage
### Gateways:
The encryptor is divided into two roles: a server and a client. The server binds to TCP port 61000 and waits for incoming connections. The client connects to the server's TCP port 61000, performs the initial handshake and key exchange, and then begins forwarding encrypted traffic.

Upon startup, both sides prompt the operator to select the post-quantum algorithm. Both sides must choose the same algorithm. After the algorithm is selected, the server and client open the TUN device tun0 and proceed to connection establishment.

##### 1st Gateway (server):
```bash
./encryptor_server [QKD IP] (optional)
```

##### 2nd Gateway (client):
```bash
./encryptor_client [Server IP] [QKD IP] (optional)
```

The server accepts the QKD system IP address as its first and only optional argument. The client accepts the server IP address as its first required argument, and the QKD system IP address as an optional second argument. This order differs from earlier revisions where the QKD IP was the leading argument on the client side.

### Endpoints:
As a result of per-packet overhead added during encryption, the final packet size will in most cases exceed the standard network MTU. Endpoints must therefore reduce their MTU to prevent fragmentation. The total per-packet overhead is approximately 56 bytes, consisting of the 12-byte AES-GCM IV, the 16-byte AES-GCM authentication tag, and the 28 bytes of outer IP and UDP headers.

```bash
ip link set [interface] mtu [MTU value]
```

The MTU value should typically be lowered to 1444 bytes when the underlying network has an MTU of 1500 bytes, accounting for the approximately 56 bytes of overhead introduced by the encryptor.

## Testing
For testing purposes, a virtual network consisting of two gateways and two endpoints was used, running on an eight-thread processor. The network topology can be seen below.

![DP-topologie drawio](https://github.com/gabsssq/Linux-network-traffic-encryptor/assets/85123006/397e2725-3582-4843-90b2-57dc2c2b38fa)

The endpoints were used to simulate a QKD system and were each given one thread. The gateways were each given two threads.

The repository also includes a standalone benchmarking utility, keyder_bench, which measures the latency and throughput of the key derivation operations in isolation. It benchmarks ML-KEM-768 key generation, encapsulation, and decapsulation, HQC-256 key generation, encapsulation, and decapsulation where supported, P-521 ECDH key generation and derivation, and the HMAC-SHA512 and SHA3-512 hashing steps used in the hybrid key derivation. This utility is useful for evaluating the computational cost of the cryptographic operations on target hardware independently of network conditions.
## Performance
#### Methodology:
The goal of the measurement was to determine the average transmission speed. Iperf3 was used. Througput was tested in settings with 1, 2 or 4 CPU cores and 576, 1300 or 1444 MTU. Generated communication was TCP and also UDP. Each value was measured during 30 seconds test. Througput was measured using ML-KEM and HQC key derivation. The endurance testing was also conducted. The tests consist of 8 hour testing phase consisting of 4 test with 2 hour duration, testing all possible PQC derivation techniques.

#### Results:
The results vary depending on the test settings. The best throughput was achieved with the 1 CPU core using ML-KEM with 1444 MTU with value of 2553 Mbps. The highest value in endurance test was with HQC TCP communication with 2160 Mbps. Average speed of key derivation is 0.111 ms for ML-KEM and 34.56 ms for HQC.

The entire measurement was performed on a processor Intel Core i7 1065G7 Ice Lake.

Setup example: 

https://github.com/gabsssq/Linux-network-traffic-encryptor/assets/85123006/8101648c-dab6-4712-9bb0-a30a66ef8830
