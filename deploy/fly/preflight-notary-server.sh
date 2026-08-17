#!/usr/bin/env bash
set -euo pipefail

app="${1:-llm-notary-prod-server}"
region="${2:-sjc}"
hostname="${3:-alice.notary.exalto.ai}"

status="$(flyctl status --app "$app" --json)"
jq -e --arg app "$app" '
  (.Name // .name // .App.Name // .app.name) == $app
' >/dev/null <<<"$status"

volumes="$(flyctl volumes list --app "$app" --json)"
jq -e --arg region "$region" '
  [.[] | select(
    (.Name // .name) == "notary_data"
    and (.Region // .region) == $region
  )] | length >= 1
' >/dev/null <<<"$volumes"

secrets="$(flyctl secrets list --app "$app" --json)"
jq -e '
  [.[] | (.Name // .name)] as $names
  | ($names | index("NOTARY_SERVER_SIGNING_KEY_B64")) != null
  and ($names | index("ADMISSION_SERVICE_TOKEN_B64")) != null
' >/dev/null <<<"$secrets"

machines="$(flyctl machines list --app "$app" --json)"
jq -e '
  [
    .[]?.image_ref
    | "\(.registry)/\(.repository)@\(.digest)"
  ] | unique
  | (length == 1)
    and (.[0] | test("@sha256:[0-9a-f]{64}$"))
' >/dev/null <<<"$machines"

certificate="$(flyctl certs show "$hostname" --app "$app" --json)"
jq -e --arg hostname "$hostname" '
  (.Hostname // .hostname) == $hostname
  and (.Configured // .configured // false) == true
' >/dev/null <<<"$certificate"

echo "Fly notary-server preflight passed for $app in $region."
