#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
restart_script="$script_dir/restart-active-machines.sh"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT
mkdir "$test_dir/bin"

cat > "$test_dir/bin/flyctl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

if [[ "$1 $2" == "machines list" ]]; then
  printf '%s\n' "$MOCK_MACHINES_JSON"
  exit 0
fi
if [[ "$1 $2" == "machine restart" ]]; then
  printf '%s\n' "${*:3}" >> "$MOCK_RESTART_LOG"
  exit 0
fi
echo "unexpected flyctl invocation: $*" >&2
exit 1
MOCK
chmod +x "$test_dir/bin/flyctl"

restart_log="$test_dir/restarts.log"
machines_json='[
  {"id":"running-1","state":"started"},
  {"id":"starting-1","state":"starting"},
  {"id":"stopped-1","state":"stopped"}
]'

PATH="$test_dir/bin:$PATH" \
MOCK_MACHINES_JSON="$machines_json" \
MOCK_RESTART_LOG="$restart_log" \
  bash "$restart_script" example-api

test "$(wc -l < "$restart_log" | tr -d ' ')" = 2
grep -Fxq -- '--app example-api --signal SIGTERM --time 30 running-1' "$restart_log"
grep -Fxq -- '--app example-api --signal SIGTERM --time 30 starting-1' "$restart_log"
if grep -Fq 'stopped-1' "$restart_log"; then
  echo "restart helper woke a stopped Machine" >&2
  exit 1
fi

: > "$restart_log"
PATH="$test_dir/bin:$PATH" \
MOCK_MACHINES_JSON='[{"id":"stopped-1","state":"stopped"}]' \
MOCK_RESTART_LOG="$restart_log" \
  bash "$restart_script" example-api
test ! -s "$restart_log"

echo "Fly active Machine restart tests passed."
