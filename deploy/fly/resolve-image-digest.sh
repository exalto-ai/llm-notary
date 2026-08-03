#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "usage: $0 <registry-image-tag>" >&2
  exit 2
fi

image_tag="$1"
attempts="${FLY_IMAGE_DIGEST_ATTEMPTS:-12}"
retry_delay="${FLY_IMAGE_DIGEST_RETRY_DELAY_SECONDS:-5}"

case "$attempts" in
  ''|*[!0-9]*)
    echo "FLY_IMAGE_DIGEST_ATTEMPTS must be a positive integer" >&2
    exit 2
    ;;
esac
case "$retry_delay" in
  ''|*[!0-9]*)
    echo "FLY_IMAGE_DIGEST_RETRY_DELAY_SECONDS must be a non-negative integer" >&2
    exit 2
    ;;
esac
if (( attempts < 1 )); then
  echo "FLY_IMAGE_DIGEST_ATTEMPTS must be a positive integer" >&2
  exit 2
fi

for (( attempt = 1; attempt <= attempts; attempt++ )); do
  manifest=""
  digest=""
  if manifest="$(docker buildx imagetools inspect "$image_tag" \
    --format '{{json .Manifest}}' 2>/dev/null)" &&
    digest="$(jq -er \
      '.digest | strings | select(test("^sha256:[0-9a-f]{64}$"))' \
      <<<"$manifest" 2>/dev/null)"; then
    printf '%s\n' "$digest"
    exit 0
  fi

  if (( attempt < attempts )); then
    printf 'Image %s is not visible with a valid digest (attempt %d/%d); retrying in %ss.\n' \
      "$image_tag" "$attempt" "$attempts" "$retry_delay" >&2
    sleep "$retry_delay"
  fi
done

printf 'Image %s did not become visible with a valid digest after %d attempts.\n' \
  "$image_tag" "$attempts" >&2
exit 1
