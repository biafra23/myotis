#!/usr/bin/env zsh

./gradlew :app:run -Pargs="beacon-status" 2>/dev/null | grep "^{"
