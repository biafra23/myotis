#!/bin/zsh

./gradlew :app:run -Pnetwork=gnosis -Pargs="status" 2>/dev/null | grep "^{"
