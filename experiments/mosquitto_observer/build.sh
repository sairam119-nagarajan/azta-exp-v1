#!/bin/sh
# Run only inside an ephemeral container made from the exact AZTA Mosquitto image.
set -eu
SOURCE_VERSION=2.1.2
SOURCE_SHA256=fd905380691ac65ea5a93779e8214941829e3d6e038d5edff9eac5fd74cbed02
apk add --no-cache build-base cjson-dev >/dev/null
wget -q "https://mosquitto.org/files/source/mosquitto-${SOURCE_VERSION}.tar.gz" -O /tmp/mosquitto.tar.gz
printf '%s  %s\n' "$SOURCE_SHA256" /tmp/mosquitto.tar.gz | sha256sum -c -
tar -xzf /tmp/mosquitto.tar.gz -C /tmp
gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -pthread \
    -I"/tmp/mosquitto-${SOURCE_VERSION}/include" \
    /poc/observer.c -o /poc/observer.so
sha256sum /poc/observer.so
gcc -std=c11 -O2 -Wall -Wextra -Werror -I"/tmp/mosquitto-${SOURCE_VERSION}/include" \
    /poc/tests/edge_cases.c -o /tmp/observer-edge-tests
/tmp/observer-edge-tests
{
    printf 'base_digest=sha256:38c0da4f2ef84284d47b3b3eeea1cb3bdeabe81ee10caf0cd5c5ff61ee3ea408\n'
    printf 'mosquitto_version=%s\nsource_sha256=%s\n' "$SOURCE_VERSION" "$SOURCE_SHA256"
    gcc --version | head -n 1
    /lib/ld-musl-x86_64.so.1 --version 2>&1 || true
    apk list --installed | sort
    sha256sum /poc/observer.c /poc/observer.so
} > /poc/build-manifest.txt
cat /poc/build-manifest.txt
