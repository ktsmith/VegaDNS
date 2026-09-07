#!/bin/sh
# Run on the tinydns host. The curl config contains the Bearer header, mode 0600.
set -eu
umask 077
: "${VEGADNS_URL:?Set the canonical HTTPS URL ending in /index.php}"
: "${VEGADNS_CURL_CONFIG:?Set the private curl configuration path}"
: "${TINYDNS_ROOT:?Set the existing tinydns root directory}"
TINYDNS_DATA=${TINYDNS_DATA:-/usr/local/bin/tinydns-data}
case "$VEGADNS_URL" in https://*/index.php) ;; *) echo 'Invalid HTTPS application URL' >&2; exit 1 ;; esac
case "$VEGADNS_URL" in *\?*|*\#*) echo 'URL must not contain query or fragment' >&2; exit 1 ;; esac
test -r "$VEGADNS_CURL_CONFIG"
test -d "$TINYDNS_ROOT"
test -x "$TINYDNS_DATA"
exec 9>"$TINYDNS_ROOT/.vegadns-publish.lock"
flock -n 9 || exit 0
stage=$(mktemp -d "$TINYDNS_ROOT/.vegadns.XXXXXXXX")
cleanup() { rm -f "$stage/data" "$stage/data.cdb" "$stage/data.tmp"; rmdir "$stage"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
curl --config "$VEGADNS_CURL_CONFIG" --proto '=https' --tlsv1.2 \
    --fail --silent --show-error --max-time 60 \
    --output "$stage/data" -- "$VEGADNS_URL?state=get_data"
test -s "$stage/data" || { echo 'Refusing empty DNS export' >&2; exit 1; }
(cd "$stage" && "$TINYDNS_DATA")
test -s "$stage/data.cdb" || { echo 'DNS compiler produced no database' >&2; exit 1; }
chmod 0644 "$stage/data" "$stage/data.cdb"
# Compile first. Rename on the same filesystem atomically switches the served CDB.
mv -f "$stage/data" "$TINYDNS_ROOT/data"
mv -f "$stage/data.cdb" "$TINYDNS_ROOT/data.cdb"
