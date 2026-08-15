#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ( $1 != smoke && $1 != full ) ]]; then
  echo "usage: $0 {smoke|full}" >&2
  exit 2
fi
profile=$1
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_dir=$(cd -- "$script_dir/.." && pwd)
project_name="llm-notary-daemon-cluster-e2e-$$"
compose=(docker compose --project-name "$project_name" --file "$repository_dir/compose.daemon-e2e.yml")

cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [[ $result -ne 0 ]]; then
    "${compose[@]}" ps >&2
    "${compose[@]}" logs --no-color postgres cluster-migrator minio setup provider notary daemon-a daemon-b cluster-ingress >&2
  fi
  if [[ ${DAEMON_E2E_KEEP:-0} != 1 ]]; then
    "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1
  fi
  exit "$result"
}
trap cleanup EXIT

if [[ ${DAEMON_E2E_SKIP_BUILD:-0} != 1 ]]; then
  "${compose[@]}" build daemon-a
fi
"${compose[@]}" up --detach cluster-ingress

for service in daemon-a daemon-b cluster-ingress; do
  for _ in $(seq 1 90); do
    container=$("${compose[@]}" ps --quiet "$service")
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)
    [[ $health == healthy ]] && break
    sleep 1
  done
  [[ $health == healthy ]] || { echo "$service did not become healthy" >&2; exit 1; }
done

basic=cluster-admin:cluster-password
admin_json() {
  local service=$1
  local path=$2
  shift 2
  "${compose[@]}" exec -T "$service" curl --fail --silent --show-error --user "$basic" "$@" "http://127.0.0.1:8788$path"
}
session_request() {
  local service=$1
  local path=$2
  shift 2
  "${compose[@]}" exec -T "$service" curl --fail --silent --show-error \
    --header 'x-llm-notary-request: dashboard' --header "cookie: $cookie" \
    "$@" "http://127.0.0.1:8788$path"
}

status_a=$(admin_json daemon-a /v1/status)
status_b=$(admin_json daemon-b /v1/status)
printf '%s' "$status_a" | "${compose[@]}" exec -T daemon-a jq -e '.runtime_profile == "cluster" and .instance_id == "daemon-a" and .lifecycle == "ready" and .metadata_backend == "postgres" and .artifact_backend == "s3"' >/dev/null
printf '%s' "$status_b" | "${compose[@]}" exec -T daemon-b jq -e '.runtime_profile == "cluster" and .instance_id == "daemon-b" and .lifecycle == "ready"' >/dev/null
replicas=$("${compose[@]}" exec -T postgres psql -U daemon_e2e -d daemon_e2e -Atc 'select count(*) from llm_notary_daemon.replicas where lease_expires_at > clock_timestamp()')
[[ $replicas == 2 ]] || { echo "expected two live replicas, got $replicas" >&2; exit 1; }

# A raw dashboard token is returned only to this client. PostgreSQL stores the
# domain-separated 32-byte digest and replica B validates/revokes it.
headers=$("${compose[@]}" exec -T daemon-a curl --silent --show-error --dump-header - --output /dev/null --user "$basic" --request POST http://127.0.0.1:8788/v1/session)
cookie=$(printf '%s\n' "$headers" | awk -F': ' 'tolower($1)=="set-cookie" {sub(/;.*/,"",$2); gsub("\r","",$2); print $2}')
[[ $cookie == llm_notary_admin_session=* ]] || { echo "cluster session cookie missing" >&2; exit 1; }
session_request daemon-b /v1/status >/dev/null
raw_token=${cookie#*=}
raw_in_database=$("${compose[@]}" exec -T postgres psql -U daemon_e2e -d daemon_e2e -Atc "select count(*) from llm_notary_daemon.dashboard_sessions where encode(token_hash,'hex')='$raw_token'")
[[ $raw_in_database == 0 ]] || { echo "raw dashboard bearer token reached PostgreSQL" >&2; exit 1; }
session_request daemon-b /v1/session --request DELETE >/dev/null
if session_request daemon-a /v1/status >/dev/null 2>&1; then
  echo "revoked cluster session remained valid" >&2
  exit 1
fi

if [[ $profile == full ]]; then
  "${compose[@]}" exec -T daemon-a curl --fail --silent --show-error \
    --dump-header /tmp/cluster-capture.headers \
    --header 'authorization: Bearer offline-cluster-secret' \
    --header 'content-type: application/json' \
    --data '{"model":"fixture-model","messages":[{"role":"user","content":"cluster cross replica prompt"}]}' \
    http://127.0.0.1:8787/openai/v1/chat/completions >/tmp/cluster-provider-response.json
  capture_id=$("${compose[@]}" exec -T daemon-a awk 'tolower($1)=="x-llm-notary-capture-id:" {gsub("\r","",$2); print $2}' /tmp/cluster-capture.headers)
  [[ $capture_id == cap-* ]] || { echo "cluster capture ID missing" >&2; exit 1; }
  capture_b=$(admin_json daemon-b "/v1/captures/$capture_id")
  printf '%s' "$capture_b" | "${compose[@]}" exec -T daemon-b jq -e --arg id "$capture_id" '.capture.capture_id==$id and .capture.capture_state=="captured" and any(.artifacts[]; .kind=="deferred_bundle")' >/dev/null

  queued=$(admin_json daemon-b "/v1/captures/$capture_id/finalizations" --request POST)
  operation_id=$(printf '%s' "$queued" | "${compose[@]}" exec -T daemon-b jq -er '.operation.operation_id')
  for _ in $(seq 1 120); do
    operation=$(admin_json daemon-a "/v1/operations/$operation_id")
    state=$(printf '%s' "$operation" | "${compose[@]}" exec -T daemon-a jq -r '.state')
    [[ $state == finalized ]] && break
    [[ $state == failed || $state == interrupted ]] && { printf '%s\n' "$operation" >&2; exit 1; }
    sleep 1
  done
  [[ $state == finalized ]] || { echo "cluster finalization timed out" >&2; exit 1; }
  admin_json daemon-a "/v1/captures/$capture_id/package" --output /tmp/cluster.llmtrace
  "${compose[@]}" exec -T daemon-a llm-notary traces verify /tmp/cluster.llmtrace \
    --trusted-notary-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 >/dev/null
  owner_rows=$("${compose[@]}" exec -T postgres psql -U daemon_e2e -d daemon_e2e -Atc "select count(*) from llm_notary_daemon.operations where operation_id='$operation_id' and owner_instance_id in ('daemon-a','daemon-b') and claim_fence is not null")
  [[ $owner_rows == 1 ]] || { echo "finalization did not retain one fenced owner" >&2; exit 1; }

  "${compose[@]}" stop daemon-b >/dev/null
  sleep 3
  "${compose[@]}" exec -T daemon-a curl --fail --silent http://127.0.0.1:8788/readyz >/dev/null
  healthy_capture=$("${compose[@]}" exec -T postgres psql -U daemon_e2e -d daemon_e2e -Atc "select capture_state from llm_notary_daemon.captures where capture_id='$capture_id'")
  [[ $healthy_capture == captured ]] || { echo "peer stop corrupted completed capture" >&2; exit 1; }
fi

echo "daemon cluster E2E passed: postgres s3 2 $profile"
