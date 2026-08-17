#!/usr/bin/env bash
set -euo pipefail

app="${1:-llm-notary-prod-api}"
public_origin="${NOTARY_API_PUBLIC_ORIGIN:-https://notary.exalto.ai}"

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
  if type == "object" then
    length >= 2
    and all(.[]; length >= 1 and all(.[]; (.status // .Status) == "passing"))
  elif type == "array" then
    length >= 2
    and all(.[]; (.status // .Status) == "passing")
  else
    false
  end
' >/dev/null <<<"$checks"

# PR5 moves the Notary to the V2 redemption contract before removing V1 from
# the API. A healthy canonical-v1 Machine is not sufficient: the immediately
# preceding dual-contract API must be live first. Authentication runs before
# body parsing, so 401 proves that the V2 activation route exists without
# issuing, redeeming, or mutating an operation.
activation_status="$(curl --silent --show-error --output /dev/null \
  --write-out '%{http_code}' --request POST --connect-timeout 10 --max-time 20 \
  "$public_origin/api/internal/notary/operations/activate")"
if [ "$activation_status" != 401 ]; then
  echo "live notary-api does not attest the V2 activation contract (HTTP $activation_status)" >&2
  exit 1
fi

echo "Fly notary-api preflight passed for $app."
