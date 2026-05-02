#!/bin/bash

# Throughput Testing Script for Linux Debian
# Tests TCP and UDP throughput across varying stream counts and MTU sizes.

export PATH=$PATH:/usr/local/bin

DEFAULT_SERVER_IP="10.0.1.8"
RESULTS_FILE="iperf_results.csv"

# Check dependencies
for cmd in iperf3 jq taskset; do
  if ! command -v $cmd &> /dev/null; then
    echo "Error: $cmd is not installed. Please install it: sudo apt install -y iperf3 jq"
    exit 1
  fi
done

echo "============================================================"
echo "          Network Encryptor Throughput Test Script          "
echo "============================================================"
echo "Prerequisites:"
echo " 1. iperf3 server must be running on the target machine: iperf3 -s"
echo " 2. Encryptors must be running and TUN interface must be up."
echo "============================================================"

read -p "Enter the KEM Algorithm currently active (e.g., ML-KEM or HQC-256): " KEM_ALG
read -p "Enter iperf3 Server IP [default $DEFAULT_SERVER_IP]: " SERVER_IP
SERVER_IP=${SERVER_IP:-$DEFAULT_SERVER_IP}

# Warn if VPN route is not detected
if ! ip route show | grep -q "via 192.168.1"; then
    echo ""
    echo "WARNING: No VPN route detected (expected 'via 192.168.1.x')."
    echo "         Traffic may NOT be passing through the encryptor."
    echo "         Results would reflect native throughput, not VPN throughput."
    echo ""
    read -p "Continue anyway? [y/N]: " CONTINUE
    [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]] && exit 1
fi

# Initialize CSV file if it doesn't exist
if [ ! -f "$RESULTS_FILE" ]; then
    echo "Date,KEM_Algorithm,Protocol,Cores_Streams,MTU_Equivalent,Throughput_Mbps,Jitter_ms,PacketLoss_pct" > "$RESULTS_FILE"
fi

AVAILABLE_CORES=$(nproc)
echo "Available CPU cores: $AVAILABLE_CORES"

CORES=(1 2 4 6 8 10)
MTUS=(576 1300 1444 9000)
PROTOCOLS=("TCP" "UDP")
TEST_DURATION=30

# Set to your actual link rate. Using the full link prevents starving the encryptor.
# If results show 100% packet loss, lower this value.
UDP_BANDWIDTH="1G"

COOLDOWN_SECS=3  # brief pause between tests to let sockets drain

for mtu in "${MTUS[@]}"; do
    echo "------------------------------------------------------------"
    echo "Testing with Equivalent MTU of $mtu..."

    # TCP: MSS = MTU - 40 (20 IP + 20 TCP headers)
    MSS=$((mtu - 40))
    # UDP: payload length = MTU - 28 (20 IP + 8 UDP headers)
    UDP_LEN=$((mtu - 28))

    for cores in "${CORES[@]}"; do
        if [ "$cores" -gt "$AVAILABLE_CORES" ]; then
            echo "  Skipping $cores streams (only $AVAILABLE_CORES cores available on this machine)"
            continue
        fi

        for proto in "${PROTOCOLS[@]}"; do
            echo "  Running -> KEM: $KEM_ALG | Proto: $proto | Streams: $cores | MTU: $mtu"

            DATE=$(date '+%Y-%m-%d %H:%M:%S')
            CORE_MASK=$((cores - 1))

            if [ "$proto" == "TCP" ]; then
                RESULT=$(taskset -c 0-$CORE_MASK iperf3 -c $SERVER_IP \
                    -t $TEST_DURATION -P $cores -M $MSS -J 2>/dev/null \
                    || echo '{"error":"iperf3 failed"}')

                # TCP: use receiver-side throughput (sum_received)
                THROUGHPUT=$(echo "$RESULT" | jq -r \
                    'if .end.sum_received.bits_per_second then
                         .end.sum_received.bits_per_second / 1000000
                     else "ERROR" end')
                JITTER="N/A"
                LOSS="N/A"

            else
                RESULT=$(taskset -c 0-$CORE_MASK iperf3 -c $SERVER_IP \
                    -u -b $UDP_BANDWIDTH -t $TEST_DURATION -P $cores -l $UDP_LEN -J 2>/dev/null \
                    || echo '{"error":"iperf3 failed"}')

                # UDP: sender rate from end.sum (sum_received does not exist for UDP)
                THROUGHPUT=$(echo "$RESULT" | jq -r \
                    'if .end.sum.bits_per_second then
                         .end.sum.bits_per_second / 1000000
                     else "ERROR" end')
                JITTER=$(echo "$RESULT" | jq -r \
                    'if .end.sum.jitter_ms != null then .end.sum.jitter_ms else "ERROR" end')
                LOSS=$(echo "$RESULT" | jq -r \
                    'if .end.sum.lost_percent != null then .end.sum.lost_percent else "ERROR" end')
            fi

            if [[ "$THROUGHPUT" != "ERROR" && -n "$THROUGHPUT" ]]; then
                THROUGHPUT=$(printf "%.2f" "$THROUGHPUT")
                echo "   => Throughput = $THROUGHPUT Mbps"
            else
                THROUGHPUT="ERROR"
                echo "   => Test failed or could not parse result."
            fi

            echo "$DATE,$KEM_ALG,$proto,$cores,$mtu,$THROUGHPUT,$JITTER,$LOSS" >> "$RESULTS_FILE"

            # Brief cooldown so kernel sockets drain before the next test
            sleep $COOLDOWN_SECS
        done
    done
done

echo "------------------------------------------------------------"
echo "Testing complete. Results saved to $RESULTS_FILE"
