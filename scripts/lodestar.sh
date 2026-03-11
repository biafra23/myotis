#!/usr/bin/env bash
# Start a Lodestar beacon node with checkpoint sync.
# Requires: docker
# Optional env: EL_ENDPOINT (execution layer JSON-RPC URL)

set -euo pipefail

EL_ENDPOINT="${EL_ENDPOINT:-http://localhost:8551}"
DATA_DIR="$(cd "$(dirname "$0")/.." && pwd)/data/lodestar"
mkdir -p "$DATA_DIR"

exec docker run --rm -it \
  --name lodestar \
  -v "$DATA_DIR:/data" \
  -p 9101:9000/tcp \
  -p 9101:9000/udp \
  -p 5053:9596/tcp \
  chainsafe/lodestar:latest \
  beacon \
  --network mainnet \
  --dataDir /data \
  --port 9000 \
  --rest \
  --rest.address 0.0.0.0 \
  --rest.port 9596 \
  --rest.cors '*' \
  --checkpointSyncUrl https://beaconstate.info \
  --execution.urls "$EL_ENDPOINT" \
  --jwtSecret /data/jwt.hex
