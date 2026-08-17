#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT
mkdir "$test_dir/bin"

python3 - "$script_dir/notary-server.fly.toml" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as source:
    config = tomllib.load(source)
assert config["env"]["NOTARY_SERVER_REGISTRY_GENERATION"] == "5"
PY

printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' >"$test_dir/bin/flyctl"
printf '%s\n' '
case "$1 $2" in
  "status --app")
    printf '\''{"Name":"llm-notary-prod-server"}\n'\''
    ;;
  "volumes list")
    printf '\''[{"Name":"notary_data","Region":"sjc"}]\n'\''
    ;;
  "secrets list")
    printf '\''[{"Name":"NOTARY_SERVER_SIGNING_KEY_B64"},{"Name":"ADMISSION_SERVICE_TOKEN_B64"}]\n'\''
    ;;
  "machines list")
    if [ "${MOCK_ZERO_MACHINES:-0}" = 1 ]; then
      printf '\''[]\n'\''
    elif [ "${MOCK_MULTIPLE_IMAGES:-0}" = 1 ]; then
      printf '\''[{"image_ref":{"registry":"registry.fly.io","repository":"one","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"image_ref":{"registry":"registry.fly.io","repository":"two","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]\n'\''
    else
      printf '\''[{"image_ref":{"registry":"registry.fly.io","repository":"llm-notary-prod-server","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]\n'\''
    fi
    ;;
  "certs show")
    printf '\''{"Hostname":"alice.notary.exalto.ai","Configured":true}\n'\''
    ;;
  *)
    echo "unexpected flyctl invocation: $*" >&2
    exit 1
    ;;
esac' >>"$test_dir/bin/flyctl"
chmod +x "$test_dir/bin/flyctl"

PATH="$test_dir/bin:$PATH" bash "$script_dir/preflight-notary-server.sh" >/dev/null
if PATH="$test_dir/bin:$PATH" MOCK_ZERO_MACHINES=1 \
    bash "$script_dir/preflight-notary-server.sh" >/dev/null 2>&1; then
  echo "preflight accepted an app without a bootstrapped Machine" >&2
  exit 1
fi
if PATH="$test_dir/bin:$PATH" MOCK_MULTIPLE_IMAGES=1 \
    bash "$script_dir/preflight-notary-server.sh" >/dev/null 2>&1; then
  echo "preflight accepted multiple current images" >&2
  exit 1
fi

echo "Fly notary-server preflight tests passed."
