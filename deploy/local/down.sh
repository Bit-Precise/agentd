#!/usr/bin/env bash
# Stops what deploy/local/up.sh started (data in .dev/ is kept).
cd "$(dirname "$0")/../.."
for name in agentrelay agentserver postgres; do
  f=".dev/$name.pid"
  [ -f "$f" ] || continue
  pid=$(cat "$f")
  kill "$pid" 2>/dev/null && echo "stopped $name"
  unlink "$f"
done
