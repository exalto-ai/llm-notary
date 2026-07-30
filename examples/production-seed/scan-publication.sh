#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 FINALIZED_PACKAGE_OR_DOWNLOADED_PAIR_DIRECTORY" >&2
  exit 2
fi

scan_root=$1
test -d "$scan_root"

case_insensitive_patterns='(authorization|proxy-authorization):[[:space:]]*(bearer|basic)[[:space:]]+[^[:space:]]|x-api-key:[[:space:]]*[^[:space:][:cntrl:]]|cookie:[[:space:]]*[^[:space:][:cntrl:]]|set-cookie:[[:space:]]*[^[:space:][:cntrl:]]|/Users/[^/[:space:]]+|/home/[^/[:space:]]+|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY'
case_sensitive_patterns='sk-[A-Za-z0-9_-]{16,}'

find "$scan_root" -type f \
  ! -name 'evidence.tlsn' \
  ! -name '*.llmbundle' \
  -exec grep -aEin "$case_insensitive_patterns" {} + && {
    echo "potential disclosure found; review every match before publication" >&2
    exit 1
  }

find "$scan_root" -type f \
  ! -name 'evidence.tlsn' \
  ! -name '*.llmbundle' \
  -exec grep -aEn "$case_sensitive_patterns" {} + && {
    echo "potential disclosure found; review every match before publication" >&2
    exit 1
  }

if find "$scan_root" -type f \( -name '*.llmbundle' -o -name 'vault.json' \) | grep -q .; then
  echo "private bundle or vault material is present" >&2
  exit 1
fi

echo "automated disclosure scan passed; manual content review is still required"
