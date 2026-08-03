#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "usage: $0 <fly-app>" >&2
  exit 2
fi

app="$1"
machines_json="$(flyctl machines list --json --app "$app")"
active_ids_json="$(jq -ce '
  [
    .[] |
    select(.state == "started" or .state == "starting") |
    .id
  ]
' <<<"$machines_json")"

while IFS= read -r machine_id; do
  # A self-stopping Machine can wake on its previous image while flyctl is
  # updating its config. Restarting after deploy makes the running process use
  # the newly pinned image. Stopped Machines already use it on their next boot.
  flyctl machine restart --app "$app" --signal SIGTERM --time 30 "$machine_id"
done < <(jq -r '.[]' <<<"$active_ids_json")
