#!/bin/sh
set -eu
: "${POC_ADMIN_PASSWORD:?synthetic admin password is required}"
: "${POC_CONFIG:?synthetic broker config is required}"
mosquitto_ctrl dynsec init /tmp/a1p-dynsec.json poc-admin "$POC_ADMIN_PASSWORD" >/dev/null
chown mosquitto:mosquitto /tmp/a1p-dynsec.json
case "$POC_CONFIG" in
    disabled)
        sed 's/plugin_opt_events .*/plugin_opt_events PUBLISH_IN/' /poc/broker-observer.conf > /tmp/broker.conf ;;
    limit)
        sed 's/plugin_opt_max_events .*/plugin_opt_max_events 10/' /poc/broker-observer.conf > /tmp/broker.conf ;;
    invalid)
        sed 's/plugin_opt_max_events .*/plugin_opt_max_events invalid/' /poc/broker-observer.conf > /tmp/broker.conf ;;
    *) cp "/poc/$POC_CONFIG" /tmp/broker.conf ;;
esac
exec mosquitto -c /tmp/broker.conf
