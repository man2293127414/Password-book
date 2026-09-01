#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo "Usage: verify-apk.sh APK_PATH" >&2
    exit 1
fi
if [ ! -f "$1" ]; then
    echo "APK file does not exist" >&2
    exit 1
fi

apksigner_command=${APKSIGNER_PATH:-}
if [ -z "$apksigner_command" ] && command -v apksigner >/dev/null 2>&1; then
    apksigner_command=$(command -v apksigner)
fi
if [ -z "$apksigner_command" ] && [ -n "${ANDROID_SDK_ROOT:-}" ]; then
    apksigner_command=$(
        find "$ANDROID_SDK_ROOT/build-tools" -type f -name apksigner -print 2>/dev/null \
            | sort -V \
            | tail -n 1
    )
fi
if [ -z "$apksigner_command" ] || [ ! -x "$apksigner_command" ]; then
    echo "Android apksigner was not found" >&2
    exit 1
fi

"$apksigner_command" verify --verbose --print-certs "$1"
