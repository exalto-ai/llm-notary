#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
state_dir=${LLM_NOTARY_SERVER_STATE_DIR:-"$repo_dir/.llm-notary-server"}
compose_file="$repo_dir/compose.daemon-server.yml"
env_file="$state_dir/.env"

usage() {
  cat <<'EOF'
Usage:
  scripts/llm-notary-server.sh init <proxy-domain> <admin-domain>
  scripts/llm-notary-server.sh up
  scripts/llm-notary-server.sh status
  scripts/llm-notary-server.sh logs
  scripts/llm-notary-server.sh down

Set LLM_NOTARY_BOOTSTRAP_API_KEY to avoid the private API-key prompt during init.
Set LLM_NOTARY_SERVER_STATE_DIR to keep generated configuration elsewhere.
EOF
}

compose() {
  test -f "$env_file" || {
    echo "Server state is not initialized. Run: $0 init <proxy-domain> <admin-domain>" >&2
    exit 1
  }
  docker compose --env-file "$env_file" -f "$compose_file" "$@"
}

valid_domain() {
  [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] && [[ $1 == *.* ]]
}

init() {
  local proxy_domain=${1:-}
  local admin_domain=${2:-}
  if [[ $EUID -eq 0 ]]; then
    echo "Run server setup as an unprivileged account that is allowed to use Docker, not with sudo." >&2
    exit 1
  fi
  if ! valid_domain "$proxy_domain" || ! valid_domain "$admin_domain" || [[ $proxy_domain == "$admin_domain" ]]; then
    echo "Provide two different DNS hostnames, for example proxy.example.com admin.example.com." >&2
    exit 1
  fi
  if [[ -e $state_dir ]]; then
    echo "Server state already exists at $state_dir; nothing was overwritten." >&2
    exit 1
  fi
  command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
  local api_key=${LLM_NOTARY_BOOTSTRAP_API_KEY:-}
  if [[ -z $api_key && -t 0 ]]; then
    read -r -s -p "Hosted LLM Notary API key: " api_key
    echo
  fi
  if [[ -z $api_key ]]; then
    echo "Set LLM_NOTARY_BOOTSTRAP_API_KEY or run init from an interactive terminal." >&2
    exit 1
  fi
  if [[ ! $api_key =~ ^llmn_v1_[0-9a-f]{32}_[0-9a-f]{64}$ ]]; then
    echo "The LLM Notary API key has an unsupported format." >&2
    exit 1
  fi
  if [[ $api_key == *$'\n'* || $api_key == *$'\r'* ]]; then
    echo "The API key contains an invalid control character." >&2
    exit 1
  fi

  umask 077
  mkdir -p "$state_dir/secrets"

  local admin_password postgres_password s3_secret
  admin_password=$(openssl rand -hex 18)
  postgres_password=$(openssl rand -hex 24)
  s3_secret=$(openssl rand -hex 24)
  printf '%s' "$admin_password" > "$state_dir/secrets/admin-password"
  printf '%s' "$api_key" > "$state_dir/secrets/api-key"
  printf '%s' "$postgres_password" > "$state_dir/secrets/postgres-password"
  printf '%s' "postgresql://llm_notary:${postgres_password}@postgres:5432/llm_notary" > "$state_dir/secrets/postgres-url"
  printf '%s' 'llm-notary' > "$state_dir/secrets/s3-access-key"
  printf '%s' "$s3_secret" > "$state_dir/secrets/s3-secret-key"
  openssl rand 32 > "$state_dir/secrets/server-vault.key"

  sed -e "s/__PROXY_DOMAIN__/$proxy_domain/g" \
      -e "s/__ADMIN_DOMAIN__/$admin_domain/g" \
      "$repo_dir/deploy/daemon-server/config.toml.template" > "$state_dir/config.toml"
  cat > "$env_file" <<EOF
SERVER_STATE_DIR=$state_dir
SERVER_UID=$(id -u)
SERVER_GID=$(id -g)
PROXY_DOMAIN=$proxy_domain
ADMIN_DOMAIN=$admin_domain
EOF
  chmod 600 "$env_file" "$state_dir/config.toml" "$state_dir"/secrets/*

  echo "Initialized LLM Notary server state at $state_dir"
  echo "Dashboard: https://$admin_domain"
  echo "Username: admin"
  echo "Generated password: $admin_password"
  echo "Save that password now, then run: $0 up"
}

case ${1:-} in
  init)
    shift
    init "$@"
    ;;
  up)
    compose up -d --build
    ;;
  status)
    compose ps
    ;;
  logs)
    compose logs --tail=200 -f daemon-a daemon-b ingress
    ;;
  down)
    compose down
    ;;
  *)
    usage
    exit 2
    ;;
esac
