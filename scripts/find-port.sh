#!/usr/bin/env bash
# Find an available port, starting from a preferred port.
# Usage: find-port.sh <preferred_port>
# Returns: the first available port starting from preferred_port

preferred=${1:?Usage: find-port.sh <preferred_port>}
port=$preferred

while [ "$port" -le $((preferred + 100)) ]; do
  if ! lsof -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "$port"
    exit 0
  fi
  port=$((port + 1))
done

echo "ERROR: No free port found in range ${preferred}-${port}" >&2
exit 1
