#!/usr/bin/env bash
# Sudo-side installer for the gnosis and mainnet Nimbus nodes that back roost.
#
#   sudo bash deploy/install-multichain-nimbus.sh            # both
#   sudo bash deploy/install-multichain-nimbus.sh gnosis     # one
#
# These are LIGHT-CLIENT SOURCES, not validating nodes: no execution client, no
# JWT, default history. See the unit files for why each of those is deliberate.
#
# Idempotent. The checkpoint sync is gated on a success marker, not on the db
# directory (Nimbus creates that before fetching, so a failed sync would
# otherwise look done), and the netkey — which fixes the node's peer id — is
# never touched once created.
set -euo pipefail

NIMBUS=/usr/bin/nimbus_beacon_node
STAGE="$(cd "$(dirname "$0")" && pwd)"

[ -x "$NIMBUS" ] || { echo "nimbus not installed at $NIMBUS"; exit 1; }

# Two live providers per chain, so a sync can be re-run against the other if one
# is down. Verified reachable 2026-08-09; beaconstate.info and
# gnosis-beacon.publicnode.com were NOT (DNS failure / 404) — do not add them
# back without checking /eth/v1/beacon/blocks/finalized/root first.
declare -A CHECKPOINT=(
  [gnosis]="https://checkpoint.gnosischain.com"
  [mainnet]="https://mainnet-checkpoint-sync.attestant.io"
)
declare -A CHECKPOINT_ALT=(
  [gnosis]="https://rpc-gbc.gnosischain.com"
  [mainnet]="https://sync-mainnet.beaconcha.in"
)
declare -A PORT=([gnosis]=9106 [mainnet]=9107)
declare -A REST=([gnosis]=5053 [mainnet]=5054)

CHAINS=("${@:-gnosis mainnet}")
# shellcheck disable=SC2206
CHAINS=(${CHAINS[*]})

id nimbus >/dev/null 2>&1 || useradd --system --home /data/nimbus --shell /usr/sbin/nologin nimbus

for chain in "${CHAINS[@]}"; do
  case "$chain" in gnosis|mainnet) ;; *) echo "unknown chain '$chain'"; exit 1 ;; esac

  dir="/data/nimbus-$chain"
  echo "=== $chain -> $dir (p2p ${PORT[$chain]}, rest 127.0.0.1:${REST[$chain]}) ==="
  mkdir -p "$dir"
  chown -R nimbus:nimbus "$dir"
  chmod 700 "$dir"

  # Checkpoint sync once. --backfill=false is what keeps this minutes rather
  # than days: it takes the finalized state and follows forward, leaving deep
  # history to roost's archive.
  #
  # Gated on a SUCCESS MARKER, not on the db directory existing. Nimbus creates
  # and opens the database before it fetches the checkpoint, so a sync that
  # fails part-way leaves $dir/db behind — and a directory check would then skip
  # the sync on the next run and enable a node with an incomplete database. The
  # marker is written only after trustedNodeSync returns 0.
  marker="$dir/.checkpoint-synced"
  if [ ! -f "$marker" ]; then
    echo "--- checkpoint sync from ${CHECKPOINT[$chain]}"
    sudo -u nimbus "$NIMBUS" trustedNodeSync \
      --network="$chain" \
      --data-dir="$dir" \
      --trusted-node-url="${CHECKPOINT[$chain]}" \
      --backfill=false \
      || {
        echo "--- primary failed, retrying from ${CHECKPOINT_ALT[$chain]}"
        sudo -u nimbus "$NIMBUS" trustedNodeSync \
          --network="$chain" \
          --data-dir="$dir" \
          --trusted-node-url="${CHECKPOINT_ALT[$chain]}" \
          --backfill=false
      }
    sudo -u nimbus touch "$marker"
  else
    echo "--- already checkpoint-synced ($marker), skipping"
  fi

  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow "${PORT[$chain]}/tcp"
    ufw allow "${PORT[$chain]}/udp"
  fi

  install -o root -g root -m 0644 "$STAGE/nimbus-$chain.service" \
    "/etc/systemd/system/nimbus-$chain.service"
done

systemctl daemon-reload
for chain in "${CHAINS[@]}"; do systemctl enable "nimbus-$chain.service"; done

cat <<'NOTE'

Installed and enabled, NOT started. Start when you are ready:

  sudo systemctl start nimbus-gnosis nimbus-mainnet
  journalctl -u nimbus-gnosis -f

Expect "Running without execution client - validator features disabled" — that is
the intended configuration, not a misconfiguration. These nodes follow the chain
optimistically and never validate execution payloads; they exist to produce
light-client data, which is derived from the beacon DAG.

Forward these on the router (tcp AND udp), or the nodes stay behind NAT and find
far fewer peers:
  gnosis 9106   mainnet 9107

Once each is following the chain, check the LC endpoints roost needs:
  curl -s -H 'Accept: application/octet-stream' \
    http://127.0.0.1:5053/eth/v1/beacon/light_client/finality_update | wc -c
  curl -s http://127.0.0.1:5053/eth/v1/node/syncing

BACK UP THE NETKEYS: /data/nimbus-<chain>/netkey. They fix each node's peer id.
Without --netkey-file Nimbus mints a fresh one per restart, which is what made
the sepolia pins die with InvalidRemotePubKey before it was set.

NOTE
