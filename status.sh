#!/bin/zsh

./gradlew :app:run -Pargs="status" 2>/dev/null | grep "^{"
