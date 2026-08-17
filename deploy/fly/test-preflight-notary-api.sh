#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT
mkdir "$test_dir/bin"

python3 - "$script_dir/notary-api.fly.toml" "$script_dir/../../.github/workflows/deploy.yml" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as source:
    config = tomllib.load(source)
assert config["env"]["NOTARY_API_DEPLOYMENT_CONTRACT"] == "canonical-v1"
assert config["vm"][0]["memory"] == "1gb"

with open(sys.argv[2], encoding="utf-8") as source:
    workflow = source.read()
server_deploy = workflow.index("- name: Deploy notary-server image")
api_deploy = workflow.index("- name: Deploy notary-api image")
assert server_deploy < api_deploy
rollback = workflow.index("- name: Restore previous images after a failed rollout")
assert workflow.index("api_rollback_succeeded=0", rollback) < workflow.index(
    'if test -e "$RUNNER_TEMP/notary-server-rollout-attempted"', rollback
)
assert "retaining the V2 server because it is compatible with both API contracts" in workflow
PY

cat >"$test_dir/bin/flyctl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

case "$1 $2" in
  "status --app")
    printf '{"Name":"llm-notary-prod-api"}\n'
    ;;
  "secrets list")
    printf '%s\n' '[
      {"Name":"NOTARY_API_DATABASE_URL"},
      {"Name":"NOTARY_API_MIGRATION_DATABASE_URL"},
      {"Name":"NOTARY_API_S3_ACCESS_KEY_ID"},
      {"Name":"NOTARY_API_S3_SECRET_ACCESS_KEY"},
      {"Name":"NOTARY_API_S3_BUCKET"},
      {"Name":"NOTARY_API_S3_ENDPOINT"},
      {"Name":"NOTARY_API_S3_REGION"},
      {"Name":"NOTARY_API_GOOGLE_CLIENT_ID"},
      {"Name":"GOOGLE_OAUTH_CLIENT_SECRET_B64"},
      {"Name":"ADMISSION_SERVICE_TOKEN_B64"},
      {"Name":"ANONYMOUS_SUBJECT_HMAC_KEY_B64"},
      {"Name":"NOTARY_REGISTRY_B64"}
    ]'
    ;;
  "machines list")
    memory="${MOCK_MEMORY_MB:-1024}"
    contract="${MOCK_CONTRACT:-canonical-v1}"
    state="${MOCK_MACHINE_STATE:-started}"
    first="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    second="$first"
    if [ "${MOCK_MULTIPLE_IMAGES:-0}" = 1 ]; then
      second="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    fi
    printf '[
      {"state":"%s","image_ref":{"registry":"registry.fly.io","repository":"api","digest":"sha256:%s"},"config":{"env":{"NOTARY_API_DEPLOYMENT_CONTRACT":"%s"},"guest":{"memory_mb":%s}}},
      {"state":"%s","image_ref":{"registry":"registry.fly.io","repository":"api","digest":"sha256:%s"},"config":{"env":{"NOTARY_API_DEPLOYMENT_CONTRACT":"%s"},"guest":{"memory_mb":%s}}}
    ]\n' "$state" "$first" "$contract" "$memory" "$state" "$second" "$contract" "$memory"
    ;;
  "checks list")
    status="${MOCK_CHECK_STATUS:-passing}"
    printf '[{"status":"%s"},{"status":"%s"}]\n' "$status" "$status"
    ;;
  *)
    echo "unexpected flyctl invocation: $*" >&2
    exit 1
    ;;
esac
MOCK
chmod +x "$test_dir/bin/flyctl"

cat >"$test_dir/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *"/api/internal/notary/operations/activate"*)
    printf '%s' "${MOCK_ACTIVATION_STATUS:-401}"
    ;;
  *)
    echo "unexpected curl invocation: $*" >&2
    exit 1
    ;;
esac
MOCK
chmod +x "$test_dir/bin/curl"

PATH="$test_dir/bin:$PATH" bash "$script_dir/preflight-notary-api.sh" >/dev/null
for invalid in \
  'MOCK_CONTRACT=legacy-v0' \
  'MOCK_MEMORY_MB=512' \
  'MOCK_MULTIPLE_IMAGES=1' \
  'MOCK_MACHINE_STATE=stopped' \
  'MOCK_CHECK_STATUS=critical' \
  'MOCK_ACTIVATION_STATUS=404'; do
  if env PATH="$test_dir/bin:$PATH" $invalid \
      bash "$script_dir/preflight-notary-api.sh" >/dev/null 2>&1; then
    echo "preflight accepted invalid Machine state: $invalid" >&2
    exit 1
  fi
done

echo "Fly notary-api preflight tests passed."
