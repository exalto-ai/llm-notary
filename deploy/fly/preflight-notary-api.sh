#!/usr/bin/env bash
set -euo pipefail

app="${1:-llm-notary-prod-api}"

status="$(flyctl status --app "$app" --json)"
jq -e --arg app "$app" '
  (.Name // .name // .App.Name // .app.name) == $app
' >/dev/null <<<"$status"

secrets="$(flyctl secrets list --app "$app" --json)"
jq -e '
  [.[] | (.Name // .name)] as $names
  | [
      "NOTARY_API_DATABASE_URL",
      "NOTARY_API_MIGRATION_DATABASE_URL",
      "NOTARY_API_S3_ACCESS_KEY_ID",
      "NOTARY_API_S3_SECRET_ACCESS_KEY",
      "NOTARY_API_S3_BUCKET",
      "NOTARY_API_S3_ENDPOINT",
      "NOTARY_API_S3_REGION",
      "NOTARY_API_GOOGLE_CLIENT_ID",
      "GOOGLE_OAUTH_CLIENT_SECRET_B64",
      "ADMISSION_SERVICE_TOKEN_B64",
      "ANONYMOUS_SUBJECT_HMAC_KEY_B64",
      "NOTARY_REGISTRY_B64"
    ]
  | all(. as $required | ($names | index($required)) != null)
' >/dev/null <<<"$secrets"

machines="$(flyctl machines list --app "$app" --json)"
jq -e '
  length >= 2
  and all(.[].state; . == "started")
  and ([
    .[]?.image_ref
    | "\(.registry)/\(.repository)@\(.digest)"
  ] | unique | length == 1)
  and all(.[].image_ref.digest; test("^sha256:[0-9a-f]{64}$"))
  and all(.[].config.env.NOTARY_API_DEPLOYMENT_CONTRACT; . == "canonical-v1")
  and all(.[].config.guest.memory_mb; . >= 1024)
' >/dev/null <<<"$machines"

checks="$(flyctl checks list --app "$app" --json)"
jq -e '
  length >= 2
  and all(.[]; (.status // .Status) == "passing")
' >/dev/null <<<"$checks"

echo "Fly notary-api preflight passed for $app."
