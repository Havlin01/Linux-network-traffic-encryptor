#!/bin/bash

# Throughput Testing Script for Linux Debian
# This script uses iperf3 to test TCP and UDP throughput across varying core/stream counts and MTU sizes.

DEFAULT_SERVER_IP="10.0.1.10"
RESULTS_FILE="iperf_results.csv"

# Check dependencies
for cmd in iperf3 jq taskset; do
  if ! command -v $cmd &> /dev/null; then
    echo "Error: $cmd is not installed. Please install it by running: sudo apt install -y iperf3 jq"
    exit 1
  fi
done

echo "============================================================"
echo "          Network Encryptor Throughput Test Script          "
echo "============================================================"
echo "Prerequisites:"
echo " 1. iperf3 server must be running on the target machine: iperf3 -s"
echo " 2. Encryptors must be running and configured with the desired KEM."
echo "============================================================"

# Interactive Prompts
read -p "Enter the KEM Algorithm currently active (e.g., ML-KEM or HQC-256): " KEM_ALG
read -p "Enter iperf3 Server IP [default $DEFAULT_SERVER_IP]: " SERVER_IP
SERVER_IP=${SERVER_IP:-$DEFAULT_SERVER_IP}

# Initialize CSV file if it doesn't exist
if [ ! -f "$RESULTS_FILE" ]; then
    echo "Date,KEM_Algorithm,Protocol,Cores_Streams,MTU_Equivalent,Throughput_Mbps,Jitter_ms,PacketLoss_pct" > "$RESULTS_FILE"
fi

# Define test parameters
CORES=(1 2 4 6 8 10)
MTUS=(576 1300 1500 9000)
PROTOCOLS=("TCP" "UDP")
TEST_DURATION=30

for mtu in "${MTUS[@]}"; do
    echo "------------------------------------------------------------"
    echo "Testing with Equivalent MTU of $mtu..."
    
    # Calculate MSS for TCP (MTU - 40 bytes for IPv4 + TCP headers)
    MSS=$((mtu - 40))
    # Calculate buffer length for UDP (MTU - 28 bytes for IPv4 + UDP headers)
    UDP_LEN=$((mtu - 28))

    for cores in "${CORES[@]}"; do
        for proto in "${PROTOCOLS[@]}"; do
            echo "Running test -> KEM: $KEM_ALG | Proto: $proto | Cores/Streams: $cores | Target MTU: $mtu"
            
            DATE=$(date '+%Y-%m-%d %H:%M:%S')
            CORE_MASK=$((cores - 1))
            
            if [ "$proto" == "TCP" ]; then
                # Run TCP test using -M to set Maximum Segment Size
                RESULT=$(taskset -c 0-$CORE_MASK iperf3 -c $SERVER_IP -t $TEST_DURATION -P $cores -M $MSS -J 2>/dev/null)
                
                # Extract results using jq
                THROUGHPUT=$(echo "$RESULT" | jq -r '.end.sum_received.bits_per_second / 1000000 | // "ERROR"')
                JITTER="N/A"
                LOSS="N/A"
                
            else
                # Run UDP test using -l to set payload length
                RESULT=$(taskset -c 0-$CORE_MASK iperf3 -c $SERVER_IP -u -b 0 -t $TEST_DURATION -P $cores -l $UDP_LEN -J 2>/dev/null)
                
                # Extract results using jq
                THROUGHPUT=$(echo "$RESULT" | jq -r '.end.sum.bits_per_second / 1000000 | // "ERROR"')
                JITTER=$(echo "$RESULT" | jq -r '.end.sum.jitter_ms | // "ERROR"')
                LOSS=$(echo "$RESULT" | jq -r '.end.sum.lost_percent | // "ERROR"')
            fi
            
            # Format numbers to 2 decimal places if valid
            if [[ "$THROUGHPUT" != "ERROR" && -n "$THROUGHPUT" ]]; then
               THROUGHPUT=$(printf "%.2f" "$THROUGHPUT")
               echo "   => Result: Throughput = $THROUGHPUT Mbps"
            else
               THROUGHPUT="ERROR"
               echo "   => Result: Test Failed or Error parsing JSON."
            fi
            
            # Append to CSV
            echo "$DATE,$KEM_ALG,$proto,$cores,$mtu,$THROUGHPUT,$JITTER,$LOSS" >> "$RESULTS_FILE"
        done
    done
done

echo "------------------------------------------------------------"
echo "Testing complete. All results have been saved to $RESULTS_FILE"
echo "You can copy this file to Excel for analysis and comparison."
