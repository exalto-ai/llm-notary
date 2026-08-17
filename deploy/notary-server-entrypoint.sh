#!/bin/sh
set -eu

private_directory=/run/notary-private
signing_source=/run/secrets/notary_signing_key
service_token_source=/run/secrets/admission_service_token
signing_target=$private_directory/notary_signing_key
service_token_target=$private_directory/admission_service_token

copy_private_file() {
    source=$1
    target=$2
    label=$3
    temporary=$target.tmp.$$

    if [ -L "$source" ] || [ ! -f "$source" ]; then
        echo "$label source must be a regular non-symlink file" >&2
        exit 1
    fi
    rm -f "$temporary"
    cp -- "$source" "$temporary"
    chmod 0400 "$temporary"
    mv -f "$temporary" "$target"
}

if [ "$#" -eq 0 ]; then
    set -- serve
fi

case "$1" in
    serve)
        umask 077
        mkdir -p "$private_directory"
        chmod 0700 "$private_directory"
        copy_private_file "$signing_source" "$signing_target" "signing key"
        copy_private_file "$service_token_source" "$service_token_target" "platform service token"
        export NOTARY_SERVER_SIGNING_KEY_FILE=$signing_target
        export NOTARY_SERVER_PLATFORM_SERVICE_TOKEN_FILE=$service_token_target
        ;;
    public-key)
        umask 077
        mkdir -p "$private_directory"
        chmod 0700 "$private_directory"
        copy_private_file "$signing_source" "$signing_target" "signing key"
        export NOTARY_SERVER_SIGNING_KEY_FILE=$signing_target
        ;;
esac

exec /usr/local/bin/notary-server "$@"
