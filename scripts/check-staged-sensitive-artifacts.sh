#!/bin/sh
# Reject sensitive local evidence and obvious credentials before they enter Git.
set -eu

blocked=0
while IFS= read -r path; do
    case "$path" in
        *.llmbundle|*.bundle.json|*.key|*.pem|*.sqlite|*/bundles/*|bundles/*|*/captures/*|captures/*|*/traces/*|traces/*|llm-notary-api.db)
            printf '%s\n' "error: refusing to stage sensitive local artifact: $path" >&2
            blocked=1
            ;;
    esac
done <<EOF
$(git diff --cached --name-only --diff-filter=ACMR)
EOF

if [ "$blocked" -ne 0 ]; then
    printf '%s\n' 'Remove the artifact from the index; use a redacted fixture when a test needs one.' >&2
    exit 1
fi

# Check only added lines and never echo a matched value. These patterns are a
# last-line-of-defense, not a replacement for reviewing every staged change.
if git diff --cached --no-ext-diff --unified=0 | grep -Eq \
    '^\+.*(-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})'; then
    printf '%s\n' 'error: staged diff appears to contain a private key or access token.' >&2
    printf '%s\n' 'Remove the credential and rotate it if it was valid.' >&2
    exit 1
fi
