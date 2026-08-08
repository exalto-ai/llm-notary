#!/bin/sh
set -eu

test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT INT TERM

build_id="0123456789abcdef0123456789abcdef01234567-test"
version="0.1.0"
fixture_root="$test_root/downloads/cli"
build_root="$fixture_root/builds/$build_id"
package="llm-notary-${version}-linux-x86_64"
archive="$package.tar.gz"
mkdir -p "$build_root" "$test_root/package/$package" "$test_root/fake-bin"
printf '%s %s\n' "$build_id" "$version" > "$fixture_root/latest"

for program in llm-notary llm-notaryd; do
  printf '#!/bin/sh\nprintf "%%s fixture\\n" "%s"\n' "$program" > "$test_root/package/$package/$program"
  chmod 0755 "$test_root/package/$package/$program"
done
tar -czf "$build_root/$archive" -C "$test_root/package" "$package"
if command -v sha256sum >/dev/null 2>&1; then
  fixture_sha256="$(sha256sum "$build_root/$archive" | awk '{print $1}')"
else
  fixture_sha256="$(shasum -a 256 "$build_root/$archive" | awk '{print $1}')"
fi
printf '%s  %s\n' "$fixture_sha256" "$archive" > "$build_root/$archive.sha256"

real_uname="$(command -v uname)"
printf '%s\n' \
  '#!/bin/sh' \
  'case "${1:-}" in' \
  "  -s) printf '%s\\n' Linux ;;" \
  "  -m) printf '%s\\n' x86_64 ;;" \
  "  *) exec \"$real_uname\" \"\$@\" ;;" \
  'esac' > "$test_root/fake-bin/uname"
chmod 0755 "$test_root/fake-bin/uname"

PATH="$test_root/fake-bin:$PATH" \
  LLM_NOTARY_DOWNLOAD_ROOT="file://$test_root/downloads/cli" \
  LLM_NOTARY_INSTALL_DIR="$test_root/bin" \
  sh "$(dirname "$0")/../public/install.sh"

test "$("$test_root/bin/llm-notary")" = "llm-notary fixture"
test "$("$test_root/bin/llm-notaryd")" = "llm-notaryd fixture"

printf 'tampered\n' >> "$build_root/$archive"
if PATH="$test_root/fake-bin:$PATH" \
    LLM_NOTARY_DOWNLOAD_ROOT="file://$test_root/downloads/cli" \
    LLM_NOTARY_INSTALL_DIR="$test_root/tampered-bin" \
    sh "$(dirname "$0")/../public/install.sh" >"$test_root/tampered.out" 2>&1; then
  echo "installer accepted an archive with the wrong checksum" >&2
  exit 1
fi
grep -q 'Checksum verification failed' "$test_root/tampered.out"

printf '../escape 0.1.0\n' > "$fixture_root/latest"
if PATH="$test_root/fake-bin:$PATH" \
    LLM_NOTARY_DOWNLOAD_ROOT="file://$test_root/downloads/cli" \
    LLM_NOTARY_INSTALL_DIR="$test_root/escaped-bin" \
    sh "$(dirname "$0")/../public/install.sh" >"$test_root/escape.out" 2>&1; then
  echo "installer accepted an unsafe build identifier" >&2
  exit 1
fi
grep -q 'build identifier is malformed' "$test_root/escape.out"

echo "Installer selects, verifies, and rejects unsafe latest artifacts."
