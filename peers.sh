#!/bin/zsh
#
./gradlew :app:run -Pargs="peers" 2>/dev/null | grep "^{" | jq -r '.connected | [.[] | select(.state == "READY") | {remoteAddress, snap, clientId}] | sort_by(.snap, .clientId) | reverse | .[] | "\(.remoteAddress) snap=\(.snap) \(.clientId)"'
