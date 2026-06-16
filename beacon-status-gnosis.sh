#!/usr/bin/env zsh

./gradlew :app:run -Pnetwork=gnosis -Pargs="beacon-status" 2>/dev/null | grep "^{"
