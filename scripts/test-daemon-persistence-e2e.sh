#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 [smoke|full]" >&2
  echo "       $0 {sqlite|postgres} filesystem 1 {smoke|full}" >&2
}

metadata_engine=sqlite
artifact_engine=filesystem
replica_count=1
profile=full
if [[ $# -eq 1 ]]; then
  profile=$1
elif [[ $# -eq 4 ]]; then
  metadata_engine=$1
  artifact_engine=$2
  replica_count=$3
  profile=$4
elif [[ $# -ne 0 ]]; then
  usage
  exit 2
fi
if [[ ( $metadata_engine != sqlite && $metadata_engine != postgres ) || $artifact_engine != filesystem || $replica_count != 1 || ( $profile != smoke && $profile != full ) ]]; then
  echo "unsupported daemon E2E matrix entry: $metadata_engine $artifact_engine $replica_count $profile" >&2
  usage
  exit 2
fi

postgres_scenarios=${DAEMON_E2E_POSTGRES_SCENARIOS:-core}
if [[ $postgres_scenarios != core && $postgres_scenarios != extended ]]; then
  echo "DAEMON_E2E_POSTGRES_SCENARIOS must be core or extended" >&2
  exit 2
fi

if [[ $metadata_engine == postgres ]]; then
  daemon_service=daemon-postgres
  daemon_config=/etc/llm-notary/config-postgres.toml
else
  daemon_service=daemon
  daemon_config=/etc/llm-notary/config.toml
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
postgres_migration_files=("$repository_dir"/crates/llm-notary-client/migrations-postgres-daemon/*.sql)
expected_postgres_migration_count=${#postgres_migration_files[@]}

cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [[ $result -ne 0 ]]; then
    "${compose[@]}" ps >&2
    "${compose[@]}" logs --no-color setup postgres migrator provider notary daemon daemon-postgres >&2
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
    container_id=$("${compose[@]}" ps --quiet "$daemon_service")
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
  "${compose[@]}" exec -T "$daemon_service" \
    llm-notary --config "$daemon_config" --json "$@"
}

assert_json() {
  local json=$1
  local expression=$2
  shift 2
  if ! printf '%s' "$json" | "${compose[@]}" exec -T "$daemon_service" jq -e "$@" "$expression" >/dev/null; then
    echo "JSON assertion failed: $expression" >&2
    printf '%s\n' "$json" >&2
    return 1
  fi
}

json_value() {
  local json=$1
  local expression=$2
  printf '%s' "$json" | "${compose[@]}" exec -T "$daemon_service" jq -er "$expression"
}

wait_for_postgres() {
  local attempts=0
  local container_id
  local health
  while (( attempts < 60 )); do
    container_id=$("${compose[@]}" ps --quiet postgres)
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
  echo "PostgreSQL did not become healthy" >&2
  return 1
}

postgres_psql() {
  "${compose[@]}" exec -T postgres \
    psql --set ON_ERROR_STOP=1 --username daemon_e2e --dbname daemon_e2e "$@"
}

run_migrator() {
  local config=${1:-/etc/llm-notary/config-postgres.toml}
  "${compose[@]}" run --rm --no-deps migrator --config "$config" migrate
}

expect_postgres_daemon_failure() {
  local scenario=$1
  local expected=$2
  local output
  local status
  set +e
  output=$("${compose[@]}" run --rm --no-deps --entrypoint /usr/bin/timeout \
    daemon-postgres 15s llm-notaryd --config /etc/llm-notary/config-postgres.toml 2>&1)
  status=$?
  set -e
  if [[ $status -eq 0 || $status -eq 124 ]]; then
    echo "PostgreSQL $scenario probe unexpectedly started the daemon" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi
  if ! grep -Eqi "$expected" <<<"$output"; then
    echo "PostgreSQL $scenario probe failed for the wrong reason" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi
}

prepare_postgres() {
  echo "starting an isolated PostgreSQL 17.7 database"
  "${compose[@]}" up --detach postgres
  wait_for_postgres
  "${compose[@]}" run --rm --no-deps setup >/dev/null

  echo "verifying the daemon refuses an unmigrated PostgreSQL schema"
  expect_postgres_daemon_failure unmigrated 'not migrated|daemon schema|schema is not current|migration journal'

  if [[ $postgres_scenarios == extended ]]; then
    echo "running two PostgreSQL migrators concurrently"
    set +e
    (run_migrator >/dev/null) &
    local first_pid=$!
    (run_migrator >/dev/null) &
    local second_pid=$!
    wait "$first_pid"
    local first_status=$?
    wait "$second_pid"
    local second_status=$?
    set -e
    if [[ $first_status -ne 0 || $second_status -ne 0 ]]; then
      echo "concurrent PostgreSQL migrators did not both complete successfully" >&2
      return 1
    fi
  fi

  echo "applying PostgreSQL metadata migrations twice to prove idempotency"
  run_migrator >/dev/null
  run_migrator >/dev/null
  local migration_count
  migration_count=$(postgres_psql --tuples-only --no-align \
    --command 'SELECT COUNT(*) FROM llm_notary_daemon.schema_migrations;')
  if [[ $migration_count != "$expected_postgres_migration_count" ]]; then
    echo "unexpected PostgreSQL daemon migration count: $migration_count (expected $expected_postgres_migration_count)" >&2
    return 1
  fi

  if [[ $postgres_scenarios == extended ]]; then
    echo "verifying the PostgreSQL migration advisory-lock timeout"
    postgres_psql >/dev/null <<'SQL' &
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('llm-notary/daemon-postgres-migrations/v1', 0));
SELECT pg_sleep(4);
COMMIT;
SQL
    local lock_holder_pid=$!
    sleep 1
    local lock_output
    local lock_status
    set +e
    lock_output=$(run_migrator /etc/llm-notary/config-postgres-lock-timeout.toml 2>&1)
    lock_status=$?
    set -e
    wait "$lock_holder_pid"
    local postgres_logs
    postgres_logs=$("${compose[@]}" logs --no-color postgres)
    if [[ $lock_status -eq 0 ]] || ! grep -Fq 'canceling statement due to lock timeout' <<<"$postgres_logs"; then
      echo "PostgreSQL migrator did not fail at the configured advisory-lock timeout" >&2
      printf '%s\n' "$lock_output" >&2
      return 1
    fi
  fi

  echo "verifying bounded failure while PostgreSQL is unavailable"
  "${compose[@]}" stop postgres >/dev/null
  expect_postgres_daemon_failure unavailable 'connect|connection|database|pool'
  local migration_output
  local migration_status
  set +e
  migration_output=$("${compose[@]}" run --rm --no-deps --entrypoint /usr/bin/timeout \
    migrator 15s llm-notaryd --config /etc/llm-notary/config-postgres.toml migrate 2>&1)
  migration_status=$?
  set -e
  if [[ $migration_status -eq 0 || $migration_status -eq 124 ]]; then
    echo "PostgreSQL migrator was not bounded while the database was unavailable" >&2
    printf '%s\n' "$migration_output" >&2
    return 1
  fi
  "${compose[@]}" up --detach postgres
  wait_for_postgres
}

assert_runtime_postgres_outage() {
  local health_status
  local readiness_status
  local status_status

  echo "verifying liveness and readiness during a live PostgreSQL outage"
  "${compose[@]}" stop postgres >/dev/null
  health_status=$("${compose[@]}" exec -T daemon-postgres \
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 10 http://127.0.0.1:8788/healthz)
  readiness_status=$("${compose[@]}" exec -T daemon-postgres \
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 10 http://127.0.0.1:8788/readyz)
  status_status=$("${compose[@]}" exec -T daemon-postgres \
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 3 http://127.0.0.1:8788/v1/status)
  if [[ $health_status != 200 || $readiness_status != 503 || $status_status != 503 ]]; then
    echo "unexpected outage probes: /healthz=$health_status /readyz=$readiness_status /v1/status=$status_status" >&2
    return 1
  fi

  "${compose[@]}" up --detach postgres
  wait_for_postgres
  wait_for_daemon
  readiness_status=$("${compose[@]}" exec -T daemon-postgres \
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 10 http://127.0.0.1:8788/readyz)
  if [[ $readiness_status != 200 ]]; then
    echo "PostgreSQL-backed readiness did not recover: /readyz=$readiness_status" >&2
    return 1
  fi
}

echo "building daemon E2E image"
if [[ ${DAEMON_E2E_SKIP_BUILD:-0} != 1 ]]; then
  "${compose[@]}" build daemon
fi

if [[ $metadata_engine == postgres ]]; then
  prepare_postgres
fi

echo "starting a fresh $metadata_engine/filesystem daemon"
"${compose[@]}" up --detach "$daemon_service"
wait_for_daemon

health_json=$("${compose[@]}" exec -T "$daemon_service" \
  curl --fail --silent --show-error http://127.0.0.1:8788/healthz)
assert_json "$health_json" '.service == "llm-notaryd" and .api_version == "v1"'

fresh_status=$(daemon_cli status)
assert_json "$fresh_status" '.counts.total_captures == 0 and .counts.active_operations == 0'

if [[ $metadata_engine == postgres ]]; then
  assert_runtime_postgres_outage
fi

echo "seeding deterministic offline persistence fixtures while the daemon is stopped"
"${compose[@]}" stop "$daemon_service"
"${compose[@]}" run --rm --no-deps --entrypoint /bin/sh "$daemon_service" -ec '
  umask 077
  mkdir -p /state/bundles
  printf "%s" "encrypted-offline-e2e-fixture" > /state/bundles/cap-e2e-recovered.llmcapture
  printf "%s" "encrypted-offline-e2e-fixture" > /state/bundles/cap-e2e-finalize.llmcapture
'
if [[ $metadata_engine == sqlite ]]; then
  "${compose[@]}" run --rm --no-deps --entrypoint sqlite3 "$daemon_service" /state/catalog.db >/dev/null <<'SQL'
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
else
  postgres_psql >/dev/null <<'SQL'
BEGIN;
INSERT INTO llm_notary_daemon.captures (
    capture_id, created_at_unix_ms, provider, operation, requested_model,
    streaming, request_bytes, prompt_preview, prompt_preview_truncated,
    config_fingerprint, capture_state, finalization_state
) VALUES (
    'cap-e2e-recovered', 1700000000000, 'openai', '/v1/responses', 'fixture-model',
    FALSE, 41, 'offline recovery fixture', FALSE,
    'sha256:offline-fixture', 'capturing', 'not_requested'
);
INSERT INTO llm_notary_daemon.captures (
    capture_id, created_at_unix_ms, completed_at_unix_ms, provider, operation,
    requested_model, response_model, http_status, streaming, request_bytes,
    response_bytes, duration_ms, prompt_preview, prompt_preview_truncated,
    output_preview, output_preview_truncated, config_fingerprint,
    capture_state, finalization_state
) VALUES (
    'cap-e2e-finalize', 1700000001000, 1700000001005, 'openai', '/v1/responses',
    'fixture-model', 'fixture-model', 200, FALSE, 43,
    29, 5, 'offline PostgreSQL fixture', FALSE,
    'offline filesystem fixture', FALSE, 'sha256:offline-fixture',
    'captured', 'not_requested'
);
INSERT INTO llm_notary_daemon.artifacts (
    capture_id, kind, locator, size_bytes, sha256, state
) VALUES (
    'cap-e2e-finalize', 'deferred_bundle',
    '/state/bundles/cap-e2e-finalize.llmcapture', 29,
    '43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d',
    'available'
);
INSERT INTO llm_notary_daemon.capture_search (
    capture_id, prompt_document, output_document
)
VALUES (
    'cap-e2e-finalize',
    to_tsvector('simple', 'offline PostgreSQL fixture'),
    to_tsvector('simple', 'offline filesystem fixture')
);
COMMIT;
SQL
fi

echo "starting the daemon and verifying recovery plus REST-backed CLI behavior"
"${compose[@]}" up --detach --no-deps "$daemon_service"
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
  provider_response=$("${compose[@]}" exec -T "$daemon_service" \
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
  full_capture_id=$("${compose[@]}" exec -T "$daemon_service" /bin/sh -ec \
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

  if "${compose[@]}" exec -T "$daemon_service" /bin/sh -ec \
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

  "${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error \
      --output /tmp/daemon-e2e.llmtrace \
      "http://127.0.0.1:8788/v1/captures/$full_capture_id/package"
  full_package_sha=$("${compose[@]}" exec -T "$daemon_service" \
    sha256sum /tmp/daemon-e2e.llmtrace | awk '{print $1}')
  file_verification=$(daemon_cli traces verify /tmp/daemon-e2e.llmtrace \
    --trusted-notary-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
  assert_json "$file_verification" '
    .capture_id == $capture_id and
    .verified == true and
    .trust_source == "explicit_key"
  ' --arg capture_id "$full_capture_id"

  echo "injecting a crash after package publication and before metadata completion"
  "${compose[@]}" stop "$daemon_service"
  "${compose[@]}" rm --force "$daemon_service"
  export DAEMON_E2E_FINALIZATION_PAUSE_MS=30000
  "${compose[@]}" up --detach --no-deps "$daemon_service"
  wait_for_daemon

  crash_response=$("${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error \
      --dump-header /tmp/daemon-e2e-crash.headers \
      --header 'authorization: Bearer offline-daemon-e2e-secret' \
      --header 'content-type: application/json' \
      --data '{"model":"fixture-model","messages":[{"role":"user","content":"offline crash-window prompt"}]}' \
      http://127.0.0.1:8787/openai/v1/chat/completions)
  assert_json "$crash_response" '.id == "chatcmpl-daemon-e2e"'
  crash_capture_id=$("${compose[@]}" exec -T "$daemon_service" /bin/sh -ec \
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
    if "${compose[@]}" exec -T "$daemon_service" test -f "$crash_package_path"; then
      crash_package_ready=1
      break
    fi
    sleep 1
  done
  if [[ $crash_package_ready != 1 ]]; then
    echo "finalization did not reach the injected post-publication pause" >&2
    exit 1
  fi
  crash_package_sha=$("${compose[@]}" exec -T "$daemon_service" sha256sum "$crash_package_path" | awk '{print $1}')
  crash_package_identity=$("${compose[@]}" exec -T "$daemon_service" stat -c '%i:%Y:%s' "$crash_package_path")
  daemon_container=$("${compose[@]}" ps --quiet "$daemon_service")
  docker kill "$daemon_container" >/dev/null

  unset DAEMON_E2E_FINALIZATION_PAUSE_MS
  "${compose[@]}" rm --force "$daemon_service"
  "${compose[@]}" up --detach --no-deps "$daemon_service"
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
  retry_package_sha=$("${compose[@]}" exec -T "$daemon_service" sha256sum "$crash_package_path" | awk '{print $1}')
  retry_package_identity=$("${compose[@]}" exec -T "$daemon_service" stat -c '%i:%Y:%s' "$crash_package_path")
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
"${compose[@]}" stop "$daemon_service"
"${compose[@]}" rm --force "$daemon_service"
"${compose[@]}" up --detach --no-deps "$daemon_service"
wait_for_daemon

restart_health=$("${compose[@]}" exec -T "$daemon_service" \
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
  "${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error \
      --output /tmp/daemon-e2e-after-restart.llmtrace \
      "http://127.0.0.1:8788/v1/captures/$full_capture_id/package"
  restart_package_sha=$("${compose[@]}" exec -T "$daemon_service" \
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

artifact_sha=$("${compose[@]}" exec -T "$daemon_service" \
  sha256sum /state/bundles/cap-e2e-finalize.llmcapture | awk '{print $1}')
if [[ $artifact_sha != 43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d ]]; then
  echo "filesystem artifact digest changed across container recreation" >&2
  exit 1
fi

if [[ $metadata_engine == sqlite ]]; then
  integrity=$("${compose[@]}" exec -T "$daemon_service" sqlite3 /state/catalog.db 'PRAGMA integrity_check;')
  if [[ $integrity != ok ]]; then
    echo "SQLite integrity check failed: $integrity" >&2
    exit 1
  fi
else
  persisted_count=$(postgres_psql --tuples-only --no-align \
    --command 'SELECT COUNT(*) FROM llm_notary_daemon.captures;')
  expected_count=2
  if [[ $profile == full ]]; then
    expected_count=4
  fi
  if [[ $persisted_count != "$expected_count" ]]; then
    echo "PostgreSQL capture count changed across daemon recreation: $persisted_count" >&2
    exit 1
  fi
  migration_count=$(postgres_psql --tuples-only --no-align \
    --command 'SELECT COUNT(*) FROM llm_notary_daemon.schema_migrations;')
  if [[ $migration_count != "$expected_postgres_migration_count" ]]; then
    echo "PostgreSQL migration journal changed unexpectedly: $migration_count (expected $expected_postgres_migration_count)" >&2
    exit 1
  fi
fi

echo "daemon persistence E2E passed: $metadata_engine filesystem 1 $profile"
