#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
resolver="$script_dir/resolve-image-digest.sh"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT
mkdir "$test_dir/bin"

cat > "$test_dir/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

count="$(cat "$MOCK_DOCKER_STATE")"
count="$((count + 1))"
printf '%s\n' "$count" > "$MOCK_DOCKER_STATE"
if (( count <= MOCK_DOCKER_FAILURES )); then
  echo "manifest unknown" >&2
  exit 1
fi
printf '{"digest":"%s"}\n' "$MOCK_DOCKER_DIGEST"
MOCK
chmod +x "$test_dir/bin/docker"

valid_digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
state_file="$test_dir/state"
retry_log="$test_dir/retry.log"
printf '0\n' > "$state_file"

resolved="$(
  PATH="$test_dir/bin:$PATH" \
  MOCK_DOCKER_STATE="$state_file" \
  MOCK_DOCKER_FAILURES=2 \
  MOCK_DOCKER_DIGEST="$valid_digest" \
  FLY_IMAGE_DIGEST_ATTEMPTS=3 \
  FLY_IMAGE_DIGEST_RETRY_DELAY_SECONDS=0 \
    bash "$resolver" registry.example.test/app:test 2>"$retry_log"
)"
test "$resolved" = "$valid_digest"
test "$(cat "$state_file")" = 3
test "$(grep -c 'retrying in 0s' "$retry_log")" = 2

printf '0\n' > "$state_file"
if PATH="$test_dir/bin:$PATH" \
  MOCK_DOCKER_STATE="$state_file" \
  MOCK_DOCKER_FAILURES=0 \
  MOCK_DOCKER_DIGEST=invalid \
  FLY_IMAGE_DIGEST_ATTEMPTS=2 \
  FLY_IMAGE_DIGEST_RETRY_DELAY_SECONDS=0 \
    bash "$resolver" registry.example.test/app:test >/dev/null 2>&1; then
  echo "resolver accepted an invalid digest" >&2
  exit 1
fi
test "$(cat "$state_file")" = 2

echo "Fly image digest resolver tests passed."
