#!/bin/sh
# Exercise publication failure ordering with fake network/compiler processes.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/vegadns-publisher.XXXXXXXX")
cleanup() {
    rm -f "$work/tools/curl" "$work/tools/tinydns-data" "$work/tools/flock" \
        "$work/curl.conf" "$work/root/data" "$work/root/data.cdb" "$work/root/.vegadns-publish.lock"
    rmdir "$work/tools" "$work/root" "$work"
}
trap cleanup EXIT
mkdir "$work/tools" "$work/root"
cat > "$work/tools/curl" <<'SCRIPT'
#!/bin/sh
set -eu
while test "$#" -gt 0; do
    if test "$1" = '--output'; then shift; output=$1; fi
    shift
done
case "$TEST_MODE" in
    download-fail) exit 22 ;;
    empty) : > "$output" ;;
    *) printf '+example.test:192.0.2.1:3600\n' > "$output" ;;
esac
SCRIPT
cat > "$work/tools/tinydns-data" <<'SCRIPT'
#!/bin/sh
test "$TEST_MODE" != compiler-fail || exit 1
printf 'new compiled database\n' > data.cdb
SCRIPT
if ! command -v flock >/dev/null 2>&1; then
    # Git for Windows lacks flock. CI on Linux exercises the real lock command.
    printf '#!/bin/sh\nexit 0\n' > "$work/tools/flock"
    chmod +x "$work/tools/flock"
    echo 'NOTE: flock unavailable; lock operation stubbed for this local test'
fi
chmod +x "$work/tools/curl" "$work/tools/tinydns-data"
export PATH="$work/tools:$PATH"
export VEGADNS_URL=https://dns.example/index.php VEGADNS_CURL_CONFIG="$work/curl.conf"
export TINYDNS_ROOT="$work/root" TINYDNS_DATA="$work/tools/tinydns-data"
printf 'header = "Authorization: Bearer test-only"\n' > "$work/curl.conf"
for mode in download-fail empty compiler-fail; do
    printf 'old database\n' > "$work/root/data.cdb"
    printf 'old source\n' > "$work/root/data"
    if TEST_MODE=$mode sh "$repo/update-data.sh" 2>/dev/null; then echo "Unexpected success: $mode" >&2; exit 1; fi
    test "$(cat "$work/root/data.cdb")" = 'old database'
    test "$(cat "$work/root/data")" = 'old source'
done
TEST_MODE=success sh "$repo/update-data.sh"
test "$(cat "$work/root/data.cdb")" = 'new compiled database'
test "$(cat "$work/root/data")" = '+example.test:192.0.2.1:3600'
echo 'PASS: publisher preserves live files on download, empty-output and compiler failures; valid output is installed'
