#!/bin/bash
# Builds OpenSSL 3.5, liboqs, oqs-provider, and the encryptors in one pass.
#
# Usage: sudo bash install.sh <other-gateway-network>
# Example: sudo bash install.sh 10.0.1.0/24

set -e

OPENSSL_VERSION="3.5.0"
OPENSSL_PREFIX="/usr/local"
OPENSSL_INC="$OPENSSL_PREFIX/include"
OPENSSL_LIB="$OPENSSL_PREFIX/lib64"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Usage ─────────────────────────────────────────────────────────────────────
if [ $# -lt 1 ] || [ "$1" = "-h" ] || [ "$1" = "-help" ]; then
    echo "Usage: sudo bash install.sh <other-gateway-network>"
    echo "       Network format: x.x.x.x/y"
    exit 1
fi
Route_IP=$1

# ── System dependencies ───────────────────────────────────────────────────────
echo "=== Installing system dependencies ==="
apt-get update -qq
apt-get install -y \
    build-essential cmake perl libz-dev \
    libboost-all-dev iperf3 jq util-linux
# requirements.txt covers any remaining apt packages
xargs apt-get install -y < "$SCRIPT_DIR/requirements.txt" || true

# ── OpenSSL 3.5 ───────────────────────────────────────────────────────────────
# The default system OpenSSL (3.0.x on Debian/Ubuntu) does not include ML-KEM.
# We build 3.5 from source and install it to /usr/local, separate from the
# system OpenSSL so nothing breaks.
if /usr/local/bin/openssl version 2>/dev/null | grep -q "$OPENSSL_VERSION"; then
    echo "=== OpenSSL $OPENSSL_VERSION already installed, skipping ==="
else
    echo "=== Building OpenSSL $OPENSSL_VERSION ==="
    cd /tmp
    wget -q "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
    tar xzf "openssl-${OPENSSL_VERSION}.tar.gz"
    cd "openssl-${OPENSSL_VERSION}"
    ./Configure --prefix="$OPENSSL_PREFIX" \
                --openssldir="$OPENSSL_PREFIX/ssl" \
                shared zlib
    make -j"$(nproc)"
    make install
    cd "$SCRIPT_DIR"
fi

# Make sure the runtime linker finds the new libraries
echo "$OPENSSL_LIB" > /etc/ld.so.conf.d/openssl35.conf
ldconfig
echo "=== OpenSSL $(/usr/local/bin/openssl version) ready ==="

# ── liboqs ────────────────────────────────────────────────────────────────────
# liboqs provides the HQC and other post-quantum implementations.
# We install it to /usr/local so oqs-provider can find it via CMake.
if pkg-config --exists liboqs 2>/dev/null && \
   [ -f "$OPENSSL_PREFIX/lib/cmake/liboqs/liboqsConfig.cmake" ]; then
    echo "=== liboqs already installed, skipping ==="
else
    echo "=== Building liboqs ==="
    cd "$SCRIPT_DIR/liboqs"
    rm -rf build
    cmake -DCMAKE_INSTALL_PREFIX="$OPENSSL_PREFIX" \
          -DCMAKE_BUILD_TYPE=Release \
          -S . -B build
    cmake --build build --parallel "$(nproc)"
    cmake --install build
    cd "$SCRIPT_DIR"
    ldconfig
fi
echo "=== liboqs ready ==="

# ── oqs-provider ──────────────────────────────────────────────────────────────
# oqs-provider bridges liboqs into OpenSSL's provider system so that HQC
# becomes available through the same EVP API as ML-KEM-768.
if [ -f "$OPENSSL_PREFIX/lib64/ossl-modules/oqsprovider.so" ] || \
   [ -f "$OPENSSL_PREFIX/lib/ossl-modules/oqsprovider.so" ]; then
    echo "=== oqs-provider already installed, skipping ==="
else
    echo "=== Building oqs-provider ==="
    cd "$SCRIPT_DIR/oqs-provider"
    rm -rf build
    cmake -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
          -DCMAKE_INSTALL_PREFIX="$OPENSSL_PREFIX" \
          -DCMAKE_PREFIX_PATH="$OPENSSL_PREFIX" \
          -S . -B build
    cmake --build build --parallel "$(nproc)"
    cmake --install build
    cd "$SCRIPT_DIR"
fi
echo "=== oqs-provider ready ==="

# ── TUN interface ─────────────────────────────────────────────────────────────
echo "=== Configuring TUN interface ==="
ip link delete tun0 2>/dev/null || true
ip tuntap add name tun0 mode tun
ip link set tun0 up
# MTU = 1500 - 20(IP) - 8(UDP) - 12(AES-GCM IV) - 16(GCM tag) = 1444
# Prevents fragmentation of encrypted packets on the underlying network.
ip link set tun0 mtu 1444
ip addr add 192.168.1.1 peer 192.168.1.2 dev tun0

echo "1" | tee /proc/sys/net/ipv4/ip_forward
ip route add "$Route_IP" via 192.168.1.2

# Clamp TCP MSS to prevent oversized segments from hitting the TUN MTU limit.
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss 1404

# Allow the 4 MB UDP socket buffers requested by the encryptors at runtime.
sysctl -w net.core.rmem_max=8388608
sysctl -w net.core.wmem_max=8388608

# ── Compile encryptors ────────────────────────────────────────────────────────
echo "=== Compiling encryptors ==="
chmod +x "$SCRIPT_DIR/sym-ExpQKD"

LIBOQS_INC="$OPENSSL_PREFIX/include"
LIBOQS_LIB="$OPENSSL_PREFIX/lib"

g++ -std=c++20 -Wall -O3 -march=native \
    -I"$OPENSSL_INC" \
    -o "$SCRIPT_DIR/encryptor_server" "$SCRIPT_DIR/encryptor_server.cpp" \
    -L"$OPENSSL_LIB" \
    -Wl,-rpath,"$OPENSSL_LIB" -Wl,-rpath,"$OPENSSL_LIB" \
    -lssl -lcrypto -loqs -pthread

g++ -std=c++20 -Wall -O3 -march=native \
    -I"$OPENSSL_INC" \
    -o "$SCRIPT_DIR/encryptor_client" "$SCRIPT_DIR/encryptor_client.cpp" \
    -L"$OPENSSL_LIB" \
    -Wl,-rpath,"$OPENSSL_LIB" \
    -lssl -lcrypto -loqs -pthread

touch "$SCRIPT_DIR/key" "$SCRIPT_DIR/keyID"

echo
echo "=== Installation complete ==="
echo "    OpenSSL : $(/usr/local/bin/openssl version)"
echo "    TUN     : tun0 (MTU 1444, 192.168.1.1 <-> 192.168.1.2)"
echo "    Route   : $Route_IP via 192.168.1.2"
echo
echo "Server : ./encryptor_server"
echo "Client : ./encryptor_client <server_ip>"
