#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out=build/lan-http-test
jar=build/deps/nanohttpd-2.3.1.jar
cd -- "$root"
mkdir -p build/deps
if [ ! -f "$jar" ]; then curl --fail --location --silent --show-error https://repo1.maven.org/maven2/org/nanohttpd/nanohttpd/2.3.1/nanohttpd-2.3.1.jar -o "$jar"; fi
expected_hash=de864c47818157141a24c9acb36df0c47d7bf15b7ff48c90610f3eb4e5df0e58
if command -v sha256sum >/dev/null 2>&1; then
    echo "$expected_hash  $jar" | sha256sum -c -
elif command -v certutil.exe >/dev/null 2>&1; then
    actual_hash=$(certutil.exe -hashfile "$jar" SHA256 | tr -d ' \r' | grep -E '^[0-9A-Fa-f]{64}$' | tr 'A-F' 'a-f')
    [ "$actual_hash" = "$expected_hash" ] || { echo "NanoHTTPD SHA-256 mismatch" >&2; exit 1; }
else
    echo "Neither sha256sum nor certutil.exe is available for NanoHTTPD verification" >&2; exit 1
fi
rm -rf -- "$out"; mkdir -p -- "$out"
find app/src/main/java/com/passwordvault/local/core -type f -name '*.java' -print | LC_ALL=C sort > "$out/sources.list"
for item in LanAddressGuard LanHttpServer WebAssetCatalog LanJson LanWireCodec LanApiDispatcher LanServiceHealthPolicy LanNetworkGuard LanServerOwner; do echo "app/src/main/java/com/passwordvault/local/lan/$item.java" >> "$out/sources.list"; done
for item in WebAssetCatalogTest LanHttpServerTest LanLifecycleTest LanApiDispatcherTest; do echo "app/src/test/java/com/passwordvault/local/lan/$item.java" >> "$out/sources.list"; done
javac -encoding UTF-8 -source 8 -target 8 -cp "$jar" -d "$out" @"$out/sources.list"
classpath="$out:$jar"
if [ "${OS:-}" = "Windows_NT" ]; then
    classpath="$out;$jar"
fi
for test in WebAssetCatalogTest LanHttpServerTest LanLifecycleTest LanApiDispatcherTest; do
    java -ea -cp "$classpath" "com.passwordvault.local.lan.$test"
done
