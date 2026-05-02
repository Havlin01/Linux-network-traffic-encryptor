#!/bin/bash

# KEM Computational Speed Test Script
# This script measures the performance of core KEM operations (keygen, encaps, decaps).

RESULTS_FILE="kem_speed_results.csv"

# Check dependencies
# This script assumes you have compiled the 'liboqs' library and its command-line
# utilities are available in your PATH. The 'speed_kem' tool is used here.
for cmd in bc speed_kem; do
  if ! command -v $cmd &> /dev/null; then
    echo "Error: Dependency '$cmd' not found."
    if [ "$cmd" == "speed_kem" ]; then
        echo "Please compile 'liboqs' and ensure its utilities (like 'speed_kem') are in your PATH."
    else
        echo "Please install it using your package manager (e.g., sudo apt install $cmd)."
    fi
    exit 1
  fi
done

echo "============================================================"
echo "          KEM Computational Speed Test Script             "
echo "============================================================"
echo "This will test the speed of KEM operations using the 'speed_kem' utility."

# Initialize CSV file
if [ ! -f "$RESULTS_FILE" ]; then
    echo "KEM_Algorithm,Operation,Iterations,Average_Time_ms" > "$RESULTS_FILE"
fi

# --- Benchmark Configuration ---
# Add the specific KEM algorithm names that the 'speed_kem' tool recognizes.
# ML-KEM-768 is standardized as CRYSTALS-Kyber.
# NOTE: The exact names may vary based on your version of liboqs.
# Run 'speed_kem --help' to see a list of supported algorithms.
KEMS_TO_TEST=("Kyber-768" "HQC-256")
OPERATIONS=("keygen" "encaps" "decaps")

for kem in "${KEMS_TO_TEST[@]}"; do
    echo "------------------------------------------------------------"
    echo "Benchmarking KEM: $kem"

    # Run the speed test once per KEM and store the full output for efficiency.
    SPEED_RESULT=$(speed_kem "$kem")
    if [ -z "$SPEED_RESULT" ]; then
        echo "  -> ERROR: Failed to get results from 'speed_kem' for $kem. Skipping."
        continue
    fi

    # Try to parse the number of iterations from the tool's output.
    # Example line: "Kyber-768 operations (1000 iterations)"
    ITERATIONS=$(echo "$SPEED_RESULT" | grep "iterations" | awk -F'[()]' '{print $2}' | awk '{print $1}')
    ITERATIONS=${ITERATIONS:-"N/A"} # Fallback if parsing fails

    for op in "${OPERATIONS[@]}"; do
        echo "  -> Analyzing operation: $op..."
        
        # Parse the stored result for the specific operation.
        # The output of speed_kem looks like: "    keygen      :   12345 cycles, 0.045 ms"
        # We use 'grep' to find the line and 'awk' to extract the 5th field (the time in ms).
        AVG_TIME_MS=$(echo "$SPEED_RESULT" | grep "$op" | awk '{print $5}')

        if [[ -n "$AVG_TIME_MS" ]]; then
            echo "    => Result: Average time = $AVG_TIME_MS ms over $ITERATIONS iterations"
            echo "$kem,$op,$ITERATIONS,$AVG_TIME_MS" >> "$RESULTS_FILE"
        else
            echo "    => Result: ERROR parsing results for $kem - $op"
            echo "$kem,$op,$ITERATIONS,ERROR" >> "$RESULTS_FILE"
        fi
    done
done

echo "------------------------------------------------------------"
echo "Benchmarking complete. All results have been saved to $RESULTS_FILE"