#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 sqlite filesystem 1 {smoke|full}" >&2
}

if [[ $# -ne 4 ]]; then
  usage
  exit 2
fi

metadata_engine=$1
artifact_engine=$2
replica_count=$3
profile=$4
if [[ $metadata_engine != sqlite || $artifact_engine != filesystem || $replica_count != 1 || ( $profile != smoke && $profile != full ) ]]; then
  echo "unsupported daemon E2E matrix entry: $metadata_engine $artifact_engine $replica_count $profile" >&2
  usage
  exit 2
fi

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Docker with the Compose plugin is required" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_dir=$(cd -- "$script_dir/.." && pwd)
compose_file="$repository_dir/compose.daemon-e2e.yml"
project_name="llm-notary-daemon-e2e-$$"
compose=(docker compose --project-name "$project_name" --file "$compose_file")

cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [[ $result -ne 0 ]]; then
    "${compose[@]}" ps >&2
    "${compose[@]}" logs --no-color setup provider notary daemon >&2
  fi
  if [[ ${DAEMON_E2E_KEEP:-0} == 1 ]]; then
    echo "preserving Docker E2E project $project_name" >&2
  else
    "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1
  fi
  exit "$result"
}
trap cleanup EXIT

wait_for_daemon() {
  local attempts=0
  local container_id
  local health
  while (( attempts < 60 )); do
    container_id=$("${compose[@]}" ps --quiet daemon)
    if [[ -n $container_id ]]; then
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)
      if [[ $health == healthy ]]; then
        return 0
      fi
      if [[ $health == exited || $health == dead ]]; then
        break
      fi
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "llm-notaryd did not become healthy" >&2
  return 1
}

daemon_cli() {
  "${compose[@]}" exec -T daemon \
    llm-notary --config /etc/llm-notary/config.toml --json "$@"
}

assert_json() {
  local json=$1
  local expression=$2
  shift 2
  if ! printf '%s' "$json" | "${compose[@]}" exec -T daemon jq -e "$@" "$expression" >/dev/null; then
    echo "JSON assertion failed: $expression" >&2
    printf '%s\n' "$json" >&2
    return 1
  fi
}

json_value() {
  local json=$1
  local expression=$2
  printf '%s' "$json" | "${compose[@]}" exec -T daemon jq -er "$expression"
}

echo "building daemon E2E image"
if [[ ${DAEMON_E2E_SKIP_BUILD:-0} != 1 ]]; then
  "${compose[@]}" build daemon
fi

echo "starting a fresh SQLite/filesystem daemon"
"${compose[@]}" up --detach daemon
wait_for_daemon

health_json=$("${compose[@]}" exec -T daemon \
  curl --fail --silent --show-error http://127.0.0.1:8788/healthz)
assert_json "$health_json" '.service == "llm-notaryd" and .api_version == "v1"'

fresh_status=$(daemon_cli status)
assert_json "$fresh_status" '.counts.total_captures == 0 and .counts.active_operations == 0'

echo "seeding deterministic offline persistence fixtures while the daemon is stopped"
"${compose[@]}" stop daemon
"${compose[@]}" run --rm --no-deps --entrypoint /bin/sh daemon -ec '
  umask 077
  mkdir -p /state/bundles
  printf "%s" "encrypted-offline-e2e-fixture" > /state/bundles/cap-e2e-recovered.llmcapture
  printf "%s" "encrypted-offline-e2e-fixture" > /state/bundles/cap-e2e-finalize.llmcapture
'
"${compose[@]}" run --rm --no-deps --entrypoint sqlite3 daemon /state/catalog.db >/dev/null <<'SQL'
PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;
INSERT INTO captures (
    capture_id, created_at_unix_ms, provider, operation, requested_model,
    streaming, request_bytes, prompt_preview, prompt_preview_truncated,
    config_fingerprint, capture_state, finalization_state
) VALUES (
    'cap-e2e-recovered', 1700000000000, 'openai', '/v1/responses', 'fixture-model',
    0, 41, 'offline recovery fixture', 0,
    'sha256:offline-fixture', 'capturing', 'not_requested'
);
INSERT INTO captures (
    capture_id, created_at_unix_ms, completed_at_unix_ms, provider, operation,
    requested_model, response_model, http_status, streaming, request_bytes,
    response_bytes, duration_ms, prompt_preview, prompt_preview_truncated,
    output_preview, output_preview_truncated, config_fingerprint,
    capture_state, finalization_state
) VALUES (
    'cap-e2e-finalize', 1700000001000, 1700000001005, 'openai', '/v1/responses',
    'fixture-model', 'fixture-model', 200, 0, 43,
    29, 5, 'offline SQLite fixture', 0,
    'offline filesystem fixture', 0, 'sha256:offline-fixture',
    'captured', 'not_requested'
);
INSERT INTO artifacts (capture_id, kind, path, size_bytes, sha256, state)
VALUES (
    'cap-e2e-finalize', 'deferred_bundle',
    '/state/bundles/cap-e2e-finalize.llmcapture', 29,
    '43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d',
    'available'
);
INSERT INTO capture_search (capture_id, prompt_preview, output_preview)
VALUES (
    'cap-e2e-finalize', 'offline SQLite fixture', 'offline filesystem fixture'
);
COMMIT;
PRAGMA wal_checkpoint(TRUNCATE);
SQL

echo "starting the daemon and verifying recovery plus REST-backed CLI behavior"
"${compose[@]}" up --detach --no-deps daemon
wait_for_daemon

recovered_status=$(daemon_cli status)
assert_json "$recovered_status" '
  .counts.total_captures == 2 and
  .counts.capturing == 0 and
  .counts.ready_to_finalize == 1
'

recovered_capture=$(daemon_cli captures show cap-e2e-recovered)
assert_json "$recovered_capture" '
  .capture.capture_state == "captured" and
  .artifacts[0].kind == "deferred_bundle" and
  .artifacts[0].size_bytes == 29 and
  .artifacts[0].sha256 == "43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d"
'

capture_page=$(daemon_cli captures list --query offline --metadata-only)
assert_json "$capture_page" '
  (.items | length) == 1 and
  .items[0].capture_id == "cap-e2e-finalize" and
  (.items[0] | has("prompt_preview") | not) and
  (.items[0] | has("output_preview") | not)
'

echo "queuing a finalization to exercise durable mutation and failure history"
finalization=$(daemon_cli finalize cap-e2e-finalize --wait)
assert_json "$finalization" '
  .deduplicated == false and
  .operation.capture_id == "cap-e2e-finalize" and
  .operation.state == "failed" and
  .operation.attempt == 1 and
  .operation.failure_code == "finalization_error"
'
operation_id=$(json_value "$finalization" '.operation.operation_id')

events=$(daemon_cli events --capture-id cap-e2e-finalize --all)
assert_json "$events" '
  any(.items[]; .event_type == "finalization_queued") and
  any(.items[]; .event_type == "finalization_failed")
'

if [[ $profile == full ]]; then
  echo "running an offline Proxy-TLS capture through the real daemon and notary fixture"
  provider_response=$("${compose[@]}" exec -T daemon \
    curl --fail --silent --show-error \
      --dump-header /tmp/daemon-e2e-capture.headers \
      --header 'authorization: Bearer offline-daemon-e2e-secret' \
      --header 'content-type: application/json' \
      --data '{"model":"fixture-model","messages":[{"role":"user","content":"offline daemon E2E prompt"}]}' \
      http://127.0.0.1:8787/openai/v1/chat/completions)
  assert_json "$provider_response" '
    .id == "chatcmpl-daemon-e2e" and
    .model == "fixture-model" and
    .choices[0].message.content == "offline daemon E2E response"
  '
  full_capture_id=$("${compose[@]}" exec -T daemon /bin/sh -ec \
    "awk 'tolower(\$1) == \"x-llm-notary-capture-id:\" {gsub(\"\\r\", \"\", \$2); print \$2}' /tmp/daemon-e2e-capture.headers")
  if [[ $full_capture_id != cap-* ]]; then
    echo "Proxy-TLS response omitted a valid capture ID" >&2
    exit 1
  fi

  full_capture=$(daemon_cli captures show "$full_capture_id")
  assert_json "$full_capture" '
    .capture.capture_id == $capture_id and
    .capture.provider == "openai" and
    .capture.operation == "/v1/chat/completions" and
    .capture.requested_model == "fixture-model" and
    .capture.response_model == "fixture-model" and
    .capture.http_status == 200 and
    .capture.capture_state == "captured" and
    .capture.finalization_state == "not_requested" and
    any(.artifacts[]; .kind == "deferred_bundle")
  ' --arg capture_id "$full_capture_id"

  full_page=$(daemon_cli captures list --query 'offline daemon E2E prompt')
  assert_json "$full_page" '
    any(.items[];
      .capture_id == $capture_id and
      .prompt_preview == "user: offline daemon E2E prompt" and
      .output_preview == "offline daemon E2E response")
  ' --arg capture_id "$full_capture_id"

  if "${compose[@]}" exec -T daemon /bin/sh -ec \
    "grep -a -F 'offline-daemon-e2e-secret' '/state/bundles/$full_capture_id.llmcapture' >/dev/null"; then
    echo "encrypted deferred bundle exposed the provider credential" >&2
    exit 1
  fi

  echo "finalizing the captured checkpoint and building a verified package"
  full_finalization=$(daemon_cli finalize "$full_capture_id" --wait)
  assert_json "$full_finalization" '
    .deduplicated == false and
    .operation.capture_id == $capture_id and
    .operation.state == "finalized" and
    .operation.attempt == 1 and
    .operation.progress.phase == "complete"
  ' --arg capture_id "$full_capture_id"
  full_operation_id=$(json_value "$full_finalization" '.operation.operation_id')

  full_trace=$(daemon_cli traces show "$full_capture_id")
  assert_json "$full_trace" '
    .capture_id == $capture_id and
    .manifest.source.provider.name == "openai" and
    .manifest.source.provider.host == "api.openai.com"
  ' --arg capture_id "$full_capture_id"

  daemon_verification=$(daemon_cli traces verify "$full_capture_id")
  assert_json "$daemon_verification" '
    .capture_id == $capture_id and .verified == true
  ' --arg capture_id "$full_capture_id"

  "${compose[@]}" exec -T daemon \
    curl --fail --silent --show-error \
      --output /tmp/daemon-e2e.llmtrace \
      "http://127.0.0.1:8788/v1/captures/$full_capture_id/package"
  full_package_sha=$("${compose[@]}" exec -T daemon \
    sha256sum /tmp/daemon-e2e.llmtrace | awk '{print $1}')
  file_verification=$(daemon_cli traces verify /tmp/daemon-e2e.llmtrace \
    --trusted-notary-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
  assert_json "$file_verification" '
    .capture_id == $capture_id and
    .verified == true and
    .trust_source == "explicit_key"
  ' --arg capture_id "$full_capture_id"

  echo "injecting a crash after package publication and before metadata completion"
  "${compose[@]}" stop daemon
  "${compose[@]}" rm --force daemon
  export DAEMON_E2E_FINALIZATION_PAUSE_MS=30000
  "${compose[@]}" up --detach --no-deps daemon
  wait_for_daemon

  crash_response=$("${compose[@]}" exec -T daemon \
    curl --fail --silent --show-error \
      --dump-header /tmp/daemon-e2e-crash.headers \
      --header 'authorization: Bearer offline-daemon-e2e-secret' \
      --header 'content-type: application/json' \
      --data '{"model":"fixture-model","messages":[{"role":"user","content":"offline crash-window prompt"}]}' \
      http://127.0.0.1:8787/openai/v1/chat/completions)
  assert_json "$crash_response" '.id == "chatcmpl-daemon-e2e"'
  crash_capture_id=$("${compose[@]}" exec -T daemon /bin/sh -ec \
    "awk 'tolower(\$1) == \"x-llm-notary-capture-id:\" {gsub(\"\\r\", \"\", \$2); print \$2}' /tmp/daemon-e2e-crash.headers")
  if [[ $crash_capture_id != cap-* ]]; then
    echo "crash-window capture omitted a valid capture ID" >&2
    exit 1
  fi
  crash_finalization=$(daemon_cli finalize "$crash_capture_id")
  crash_operation_id=$(json_value "$crash_finalization" '.operation.operation_id')

  crash_package_path="/state/traces/$crash_capture_id.llmtrace"
  crash_package_ready=0
  for _ in $(seq 1 90); do
    if "${compose[@]}" exec -T daemon test -f "$crash_package_path"; then
      crash_package_ready=1
      break
    fi
    sleep 1
  done
  if [[ $crash_package_ready != 1 ]]; then
    echo "finalization did not reach the injected post-publication pause" >&2
    exit 1
  fi
  crash_package_sha=$("${compose[@]}" exec -T daemon sha256sum "$crash_package_path" | awk '{print $1}')
  crash_package_identity=$("${compose[@]}" exec -T daemon stat -c '%i:%Y:%s' "$crash_package_path")
  daemon_container=$("${compose[@]}" ps --quiet daemon)
  docker kill "$daemon_container" >/dev/null

  unset DAEMON_E2E_FINALIZATION_PAUSE_MS
  "${compose[@]}" rm --force daemon
  "${compose[@]}" up --detach --no-deps daemon
  wait_for_daemon

  interrupted=$(daemon_cli operations show "$crash_operation_id")
  assert_json "$interrupted" '
    .state == "interrupted" and .attempt == 1 and .retryable == true
  '
  daemon_cli operations retry "$crash_operation_id" >/dev/null
  crash_final_state=""
  for _ in $(seq 1 90); do
    crash_final_state=$(daemon_cli operations show "$crash_operation_id")
    state=$(json_value "$crash_final_state" '.state')
    if [[ $state == finalized ]]; then
      break
    fi
    if [[ $state == failed ]]; then
      echo "orphan-package retry failed" >&2
      printf '%s\n' "$crash_final_state" >&2
      exit 1
    fi
    sleep 1
  done
  assert_json "$crash_final_state" '
    .state == "finalized" and
    .attempt == 2 and
    (.attempt_history | length) == 2 and
    .attempt_history[0].state == "finalized" and
    .attempt_history[1].state == "interrupted"
  '
  retry_package_sha=$("${compose[@]}" exec -T daemon sha256sum "$crash_package_path" | awk '{print $1}')
  retry_package_identity=$("${compose[@]}" exec -T daemon stat -c '%i:%Y:%s' "$crash_package_path")
  if [[ $retry_package_sha != "$crash_package_sha" || $retry_package_identity != "$crash_package_identity" ]]; then
    echo "retry replaced rather than reused the orphan package" >&2
    exit 1
  fi
  crash_events=$(daemon_cli events --operation-id "$crash_operation_id" --all)
  assert_json "$crash_events" '
    ([.items[] | select(.event_type == "finalization_completed")] | length) == 1
  '
fi

echo "removing and recreating the app container with the same durable volume"
"${compose[@]}" stop daemon
"${compose[@]}" rm --force daemon
"${compose[@]}" up --detach --no-deps daemon
wait_for_daemon

restart_health=$("${compose[@]}" exec -T daemon \
  curl --fail --silent --show-error http://127.0.0.1:8788/healthz)
assert_json "$restart_health" '.service == "llm-notaryd" and .api_version == "v1"'

restart_status=$(daemon_cli status)
if [[ $profile == full ]]; then
  assert_json "$restart_status" '
    .counts.total_captures == 4 and
    .counts.finalized == 2 and
    .counts.failed == 1 and
    .counts.active_operations == 0
  '
else
  assert_json "$restart_status" '
    .counts.total_captures == 2 and
    .counts.failed == 1 and
    .counts.active_operations == 0
  '
fi

persisted_operation=$(daemon_cli operations show "$operation_id")
assert_json "$persisted_operation" '
  .operation_id == $operation_id and
  .capture_id == "cap-e2e-finalize" and
  .state == "failed" and
  .attempt == 1 and
  .failure_code == "finalization_error"
' --arg operation_id "$operation_id"

persisted_capture=$(daemon_cli captures show cap-e2e-finalize)
assert_json "$persisted_capture" '
  .capture.capture_state == "captured" and
  .capture.finalization_state == "failed" and
  .artifacts[0].sha256 == "43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d"
'

if [[ $profile == full ]]; then
  persisted_full_operation=$(daemon_cli operations show "$full_operation_id")
  assert_json "$persisted_full_operation" '
    .operation_id == $operation_id and
    .capture_id == $capture_id and
    .state == "finalized" and
    .attempt == 1 and
    .progress.phase == "complete"
  ' --arg operation_id "$full_operation_id" --arg capture_id "$full_capture_id"

  persisted_full_capture=$(daemon_cli captures show "$full_capture_id")
  assert_json "$persisted_full_capture" '
    .capture.capture_state == "captured" and
    .capture.finalization_state == "finalized" and
    any(.artifacts[]; .kind == "finalized_package")
  '
  "${compose[@]}" exec -T daemon \
    curl --fail --silent --show-error \
      --output /tmp/daemon-e2e-after-restart.llmtrace \
      "http://127.0.0.1:8788/v1/captures/$full_capture_id/package"
  restart_package_sha=$("${compose[@]}" exec -T daemon \
    sha256sum /tmp/daemon-e2e-after-restart.llmtrace | awk '{print $1}')
  if [[ $restart_package_sha != "$full_package_sha" ]]; then
    echo "verified package digest changed across container recreation" >&2
    exit 1
  fi
  restart_verification=$(daemon_cli traces verify /tmp/daemon-e2e-after-restart.llmtrace \
    --trusted-notary-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
  assert_json "$restart_verification" '
    .capture_id == $capture_id and .verified == true
  ' --arg capture_id "$full_capture_id"
fi

artifact_sha=$("${compose[@]}" exec -T daemon \
  sha256sum /state/bundles/cap-e2e-finalize.llmcapture | awk '{print $1}')
if [[ $artifact_sha != 43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d ]]; then
  echo "filesystem artifact digest changed across container recreation" >&2
  exit 1
fi

integrity=$("${compose[@]}" exec -T daemon sqlite3 /state/catalog.db 'PRAGMA integrity_check;')
if [[ $integrity != ok ]]; then
  echo "SQLite integrity check failed: $integrity" >&2
  exit 1
fi

echo "daemon persistence E2E passed: sqlite filesystem 1 $profile"
