#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_directory="build/core-test"

cd -- "$project_root"
rm -rf -- "$output_directory"
mkdir -p -- "$output_directory"

find app/src/main/java/com/passwordvault/local/core app/src/test/java/com/passwordvault/local/core \
    -type f -name '*.java' -print | LC_ALL=C sort > "$output_directory/sources.list"

if [ -d app/src/main/java/com/passwordvault/local/ui ]; then
    find app/src/main/java/com/passwordvault/local/ui -maxdepth 1 \
        -type f -name '*Controller.java' -print | LC_ALL=C sort >> "$output_directory/sources.list"
fi

javac -encoding UTF-8 -source 8 -target 8 \
    -d "$output_directory" \
    @"$output_directory/sources.list"

java -Dpasswordvault.projectRoot="$project_root" -ea -cp "$output_directory" \
    com.passwordvault.local.core.CoreTestMain
