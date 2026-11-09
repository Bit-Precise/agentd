#!/usr/bin/env bash
# Runs PostgreSQL, agentserver and one agentrelay on this machine for trying
# agentd out. Everything lives in .dev/ and uses *.localhost names, which
# resolve to the loopback address. Stop with deploy/local/down.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."
DEV="$PWD/.dev"
mkdir -p "$DEV" bin

make build >/dev/null
go build -o bin/devpg ./tools/devpg

start() { # name, command...
  local name=$1; shift
  if [ -f "$DEV/$name.pid" ] && kill -0 "$(cat "$DEV/$name.pid")" 2>/dev/null; then
    echo "$name already running (pid $(cat "$DEV/$name.pid"))"; return
  fi
  nohup "$@" >"$DEV/$name.log" 2>&1 &
  echo $! >"$DEV/$name.pid"
  echo "started $name (log: .dev/$name.log)"
}

if [ ! -f "$DEV/env.sh" ]; then
  cat >"$DEV/env.sh" <<ENV
export AGENTSERVER_ADMIN_TOKEN=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
export AGENTSERVER_STATE_KEY=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
export AGENTSERVER_RELAY_TOKEN=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
export AGENTSERVER_ADMIN_URL=http://127.0.0.1:7800
export AGENTSERVER_DATABASE_URL=postgres://agentd:agentd@127.0.0.1:55432/agentd?sslmode=disable
export AGENTD_EXTRA_ROOTS=$DEV/relay-ca.pem,$DEV/server-ca.pem
ENV
fi
# shellcheck disable=SC1091
. "$DEV/env.sh"

cat >"$DEV/agentserver.yaml" <<CFG
apiVersion: agentd/v1
kind: AgentserverConfiguration
domain: agentsrv.localhost
listen: 127.0.0.1:8443
admin_listen: 127.0.0.1:7800
tls: { mode: selfsigned, ca_out: $DEV/server-ca.pem }
relay_join_token_env: AGENTSERVER_RELAY_TOKEN
CFG
cat >"$DEV/agentrelay.yaml" <<CFG
apiVersion: agentd/v1
kind: AgentrelayConfiguration
name: relay-local
domain: relay.localhost
listen: 127.0.0.1:9443
key_file: $DEV/relay.key
control: { url: "https://agentsrv.localhost:8443", ca_file: $DEV/server-ca.pem, join_token_env: AGENTSERVER_RELAY_TOKEN }
tls: { mode: selfsigned, ca_out: $DEV/relay-ca.pem }
CFG

start postgres bin/devpg -port 55432 -data "$DEV/pg"
for _ in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/55432) 2>/dev/null && break; sleep 1; done
start agentserver bin/agentserver run -c "$DEV/agentserver.yaml"
for _ in $(seq 1 30); do curl -fs http://127.0.0.1:7800/healthz >/dev/null 2>&1 && break; sleep 1; done
start agentrelay bin/agentrelay run -c "$DEV/agentrelay.yaml"
for _ in $(seq 1 30); do bin/agentserver relay list 2>/dev/null | grep -q 'relay-local.*yes' && break; sleep 1; done

cat <<MSG

agentserver console: http://127.0.0.1:7800   (admin token: $AGENTSERVER_ADMIN_TOKEN)

Next steps (in a shell with: source .dev/env.sh):
  bin/agentserver workspace create home --relay relay-local
  bin/agentserver token create -w home --name laptop
  bin/agentd --home .dev/laptop join '<link>'
  # enable roles in .dev/laptop/config.yaml, then:
  bin/agentd --home .dev/laptop run
MSG
