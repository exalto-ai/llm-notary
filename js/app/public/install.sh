#!/bin/sh
# Install the latest LLM Notary CLI for Apple silicon macOS or Linux.
set -eu

download_root="${LLM_NOTARY_DOWNLOAD_ROOT:-https://notary.exalto.ai/downloads/cli}"
channel="${LLM_NOTARY_CHANNEL:-latest}"
install_dir="${LLM_NOTARY_INSTALL_DIR:-${HOME}/.local/bin}"

case "$channel" in
  ""|.*|*..*|*[!a-zA-Z0-9._-]*)
    echo "Invalid LLM Notary release channel: $channel" >&2
    exit 1
    ;;
esac

system="$(uname -s)"
machine="$(uname -m)"

case "$system" in
  Darwin) platform="darwin" ;;
  Linux) platform="linux" ;;
  *) echo "LLM Notary supports macOS and Linux through this installer." >&2; exit 1 ;;
esac

case "$machine" in
  x86_64|amd64) architecture="x86_64" ;;
  arm64|aarch64) architecture="aarch64" ;;
  *) echo "Unsupported CPU architecture: $machine" >&2; exit 1 ;;
esac

if [ "$platform" = "darwin" ] && [ "$architecture" != "aarch64" ]; then
  echo "LLM Notary supports Apple silicon Macs; Intel Macs are not supported." >&2
  exit 1
fi

pointer="$(curl -fsSL "$download_root/$channel")"
case "$pointer" in
  *" "*) ;;
  *) echo "The $channel release pointer is malformed" >&2; exit 1 ;;
esac
build_id="${pointer%% *}"
version="${pointer#* }"
case "$build_id" in
  ""|.*|*..*|*[!a-zA-Z0-9._-]*)
    echo "The $channel build identifier is malformed" >&2
    exit 1
    ;;
esac
case "$version" in
  ""|.*|*..*|*" "*|*[!a-zA-Z0-9._-]*)
    echo "The $channel version is malformed" >&2
    exit 1
    ;;
esac

archive="llm-notary-${version}-${platform}-${architecture}.tar.gz"
build_url="$download_root/builds/$build_id"
temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT INT TERM

curl -fsSL "$build_url/$archive" -o "$temporary_dir/$archive"
curl -fsSL "$build_url/$archive.sha256" -o "$temporary_dir/$archive.sha256"
expected="$(awk '{print $1}' "$temporary_dir/$archive.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$temporary_dir/$archive" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$temporary_dir/$archive" | awk '{print $1}')"
fi
if [ "$expected" != "$actual" ]; then
  echo "Checksum verification failed for $archive" >&2
  exit 1
fi

tar -xzf "$temporary_dir/$archive" -C "$temporary_dir"
mkdir -p "$install_dir"
install -m 0755 "$temporary_dir/llm-notary-${version}-${platform}-${architecture}/llm-notary" "$install_dir/llm-notary"
install -m 0755 "$temporary_dir/llm-notary-${version}-${platform}-${architecture}/notaryd" "$install_dir/notaryd"

echo "Installed LLM Notary $version from $channel (llm-notary and notaryd) to $install_dir"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "Add $install_dir to your PATH, then run: notaryd" ;;
esac
