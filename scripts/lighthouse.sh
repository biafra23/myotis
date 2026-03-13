#!/usr/bin/env bash
# Start a Lighthouse beacon node with checkpoint sync and light client serving.
# Requires: docker, local Geth running on host with auth RPC on port 8551.
# Uses Geth's jwt.hex from /home/biafra/geth/jwt.hex.

set -euo pipefail

JWT_FILE="${JWT_FILE:-/home/biafra/geth/jwt.hex}"
DATA_DIR="$(cd "$(dirname "$0")/.." && pwd)/data/lighthouse"
mkdir -p "$DATA_DIR"

exec docker run --rm -d \
  --name lighthouse \
  --network host \
  -v "$DATA_DIR:/root/.lighthouse" \
  -v "$JWT_FILE:/jwt.hex:ro" \
  sigp/lighthouse:latest \
  lighthouse bn \
  --network mainnet \
  --listen-address 0.0.0.0 \
  --port 9100 \
  --http \
  --http-address 0.0.0.0 \
  --http-port 5052 \
  --http-allow-origin '*' \
  --checkpoint-sync-url https://beaconstate.info \
  --execution-endpoint http://127.0.0.1:8551 \
  --execution-jwt /jwt.hex
