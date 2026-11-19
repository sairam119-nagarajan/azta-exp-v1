#!/bin/sh
# Run only inside the disposable synthetic broker container.
set -eu
: "${POC_ADMIN_PASSWORD:?}"
: "${POC_A_PASSWORD:?}"
: "${POC_B_PASSWORD:?}"
: "${POC_READER_PASSWORD:?}"
ctrl() {
    mosquitto_ctrl -h 127.0.0.1 -p 1883 -u poc-admin -P "$POC_ADMIN_PASSWORD" dynsec "$@" >/dev/null 2>/dev/null
}
ctrl setDefaultACLAccess publishClientSend deny
ctrl setDefaultACLAccess publishClientReceive deny
ctrl setDefaultACLAccess subscribe deny
ctrl setDefaultACLAccess unsubscribe deny
ctrl createRole poc-publisher
ctrl addRoleACL poc-publisher publishClientSend poc/shared allow
ctrl addRoleACL poc-publisher publishClientSend poc/other allow
ctrl addRoleACL poc-publisher publishClientSend poc/long/# allow
ctrl addClientRole poc-admin poc-publisher
ctrl createRole poc-reader-role
ctrl addRoleACL poc-reader-role subscribeLiteral poc/shared allow
ctrl addRoleACL poc-reader-role publishClientReceive poc/shared allow
ctrl createClient poc-a -i poc-a -p "$POC_A_PASSWORD"
ctrl addClientRole poc-a poc-publisher
ctrl createClient poc-b -i poc-b -p "$POC_B_PASSWORD"
ctrl addClientRole poc-b poc-publisher
ctrl createClient poc-reader -i poc-reader -p "$POC_READER_PASSWORD"
ctrl addClientRole poc-reader poc-reader-role
printf 'Synthetic Dynamic Security policy ready.\n'
