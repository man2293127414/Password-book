#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo "Usage: prepare-signing.sh OUTPUT_DIRECTORY" >&2
    exit 1
fi
if [ -z "${ANDROID_KEYSTORE_BASE64:-}" ]; then
    echo "ANDROID_KEYSTORE_BASE64 is required" >&2
    exit 1
fi

umask 077
output_directory=$1
output_path="$output_directory/android-release.jks"
temporary_path="$output_directory/.android-release.jks.tmp.$$"

mkdir -p -- "$output_directory"
trap 'rm -f -- "$temporary_path"' EXIT HUP INT TERM

if command -v base64 >/dev/null 2>&1; then
    if ! printf '%s' "$ANDROID_KEYSTORE_BASE64" | base64 --decode > "$temporary_path"; then
        echo "ANDROID_KEYSTORE_BASE64 is not valid base64" >&2
        exit 1
    fi
elif command -v node >/dev/null 2>&1; then
    if ! printf '%s' "$ANDROID_KEYSTORE_BASE64" | node -e '
const fs = require("fs");
const value = fs.readFileSync(0, "utf8").trim();
const normalized = value.replace(/=+$/, "");
const decoded = Buffer.from(value, "base64");
if (!value || decoded.toString("base64").replace(/=+$/, "") !== normalized) process.exit(2);
process.stdout.write(decoded);
' > "$temporary_path"; then
        echo "ANDROID_KEYSTORE_BASE64 is not valid base64" >&2
        exit 1
    fi
else
    echo "A base64 decoder is required" >&2
    exit 1
fi

if [ ! -s "$temporary_path" ]; then
    echo "Decoded Android keystore is empty" >&2
    exit 1
fi

if command -v chmod >/dev/null 2>&1; then
    chmod 600 "$temporary_path"
elif [ "${OS:-}" != "Windows_NT" ]; then
    echo "chmod is required on this platform" >&2
    exit 1
fi
mv -f -- "$temporary_path" "$output_path"
trap - EXIT HUP INT TERM
printf '%s\n' "$output_path"
