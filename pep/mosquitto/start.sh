#!/bin/sh
set -eu

state=/mosquitto/data/dynamic-security.json
init=/mosquitto/data/.dynsec-admin-init
source_secret=/run/secrets/dynsec_admin_password

if [ ! -s $state ]; then
    if [ ! -s $source_secret ]; then
        echo AZTA: missing Dynamic Security bootstrap secret >&2
        exit 1
    fi
    umask 077
    cp $source_secret $init
    chown mosquitto:mosquitto $init
    chmod 0600 $init
fi

exec /docker-entrypoint.sh mosquitto -c /mosquitto/config/mosquitto.conf
