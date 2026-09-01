#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_directory="build/signing-test"

cd -- "$project_root"
rm -rf -- "$test_directory"
mkdir -p -- "$test_directory/input" "$test_directory/output"
trap 'rm -rf -- "$test_directory"' EXIT HUP INT TERM

source_keystore="$test_directory/input/test-release.jks"
keytool -genkeypair \
    -keystore "$source_keystore" \
    -storepass test-only-password \
    -keypass test-only-password \
    -alias test-key \
    -keyalg RSA \
    -keysize 2048 \
    -validity 1 \
    -dname "CN=Password Vault Test" \
    -noprompt >/dev/null 2>&1

ANDROID_KEYSTORE_BASE64=$(node -e 'process.stdout.write(require("fs").readFileSync(process.argv[1]).toString("base64"))' "$source_keystore")
export ANDROID_KEYSTORE_BASE64

prepared_path=$(scripts/prepare-signing.sh "$test_directory/output")
expected_path="$test_directory/output/android-release.jks"

if [ "$prepared_path" != "$expected_path" ]; then
    echo "prepare-signing returned an unexpected path" >&2
    exit 1
fi
if [ ! -f "$prepared_path" ]; then
    echo "prepare-signing did not create a keystore" >&2
    exit 1
fi
if ! cmp -s "$source_keystore" "$prepared_path"; then
    echo "prepared keystore differs from its source" >&2
    exit 1
fi
if find . -type f -name 'android-release.jks' ! -path "./$expected_path" | grep -q .; then
    echo "prepare-signing wrote outside the requested directory" >&2
    exit 1
fi

echo "PASS test-prepare-signing"
