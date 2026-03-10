#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <spec-name>" >&2
    exit 2
fi

SPEC="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TLA_DIR="$PROJECT_DIR/formal/tla"
JAR_PATH="$TLA_DIR/tla2tools.jar"
CFG_PATH="$TLA_DIR/${SPEC}.cfg"
MAIN_PATH="$TLA_DIR/${SPEC}.tla"
MC_PATH="$TLA_DIR/MC_${SPEC}.tla"
JAVA_OPTS="${TLA_JAVA_OPTS:-"-Xms512m -Xmx10g -XX:+UseParallelGC"}"

if [ ! -f "$CFG_PATH" ]; then
    echo "Missing TLA+ config: $CFG_PATH" >&2
    exit 1
fi

if [ -f "$MC_PATH" ]; then
    TARGET_PATH="$MC_PATH"
    TARGET_LABEL="via MC_${SPEC}"
elif [ -f "$MAIN_PATH" ]; then
    TARGET_PATH="$MAIN_PATH"
    TARGET_LABEL="direct"
else
    echo "Missing TLA+ module for spec $SPEC" >&2
    exit 1
fi

echo "=== TLA+ $SPEC ($TARGET_LABEL) ==="

if [ "${TLA_DRY_RUN:-0}" = "1" ]; then
    echo "java $JAVA_OPTS -jar $JAR_PATH -config $CFG_PATH $TARGET_PATH"
    exit 0
fi

if [ ! -f "$JAR_PATH" ]; then
    echo "Missing TLA+ tools jar: $JAR_PATH" >&2
    exit 1
fi

cd "$TLA_DIR"

# Intentional word splitting for user-supplied JVM flags.
# shellcheck disable=SC2086
java $JAVA_OPTS -jar "$JAR_PATH" -config "$CFG_PATH" "$TARGET_PATH"
