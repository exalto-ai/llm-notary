#!/bin/sh
# Install the latest LLM Notary CLI for macOS or Linux.
set -eu

repo="exalto-ai/llm-notary"
base_url="https://github.com/$repo/releases/download"
install_dir="${LLM_NOTARY_INSTALL_DIR:-${HOME}/.local/bin}"

if [ -n "${LLM_NOTARY_VERSION:-}" ]; then
  tag="${LLM_NOTARY_VERSION}"
  case "$tag" in v*) ;; *) tag="v$tag";; esac
else
  tag="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest" | sed 's#.*/##')"
fi

case "$(uname -s)" in
  Darwin) platform="darwin" ;;
  Linux) platform="linux" ;;
  *) echo "LLM Notary supports macOS and Linux through this installer. Download the Windows archive from GitHub Releases." >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) architecture="x86_64" ;;
  arm64|aarch64) architecture="aarch64" ;;
  *) echo "Unsupported CPU architecture: $(uname -m)" >&2; exit 1 ;;
esac

version="${tag#v}"
archive="llm-notary-${version}-${platform}-${architecture}.tar.gz"
temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT INT TERM

curl -fsSL "$base_url/$tag/$archive" -o "$temporary_dir/$archive"
curl -fsSL "$base_url/$tag/$archive.sha256" -o "$temporary_dir/$archive.sha256"
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

echo "Installed LLM Notary $tag to $install_dir"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "Add $install_dir to your PATH, then run: llm-notary --help" ;;
esac
