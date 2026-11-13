#!/bin/sh
# Invoked in a PRIVATE mount namespace by pam-bus.sh; never directly on the host.
set -eu
[ "$(id -u)" -eq 0 ] || exit 77
[ "$#" -eq 6 ] || { echo 'usage: private-pam.sh GREETD DAEMON MODULE ENTRY DRIVER NATIVE_CLIENT' >&2; exit 2; }
# The wrapper must already have made all mounts private.
[ "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ] || exit 77
base=$(mktemp -d /tmp/greetd-pam-bus.XXXXXXXX)
chmod 755 "$base"
bus_pid= daemon_a= daemon_b=
cleanup() {
    for pid in "$daemon_a" "$daemon_b" "$bus_pid"; do
        if [ -n "$pid" ]; then kill -CONT "$pid" 2>/dev/null || :; kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
    done
    if [ "${KEEP_FIXTURES:-0}" = 1 ]; then echo "fixtures: $base" >&2; else rm -rf "$base"; fi
}
trap cleanup EXIT HUP INT TERM
mkdir -m 700 "$base/fixture-a" "$base/fixture-b" "$base/pam"
mkdir -m 1777 "$base/reports"
: > "$base/fixture-a/node"
: > "$base/fixture-b/node"
printf 'not for the application\n' > "$base/unrelated-secret"
cp "$3" "$base/pam-seat.so"
cp "$4" "$base/entry.py"
cp "$6" "$base/native-client"
chmod 755 "$base/native-client"
for service in seat-test seat-optional; do
    printf 'auth required %s/pam-seat.so\naccount required %s/pam-seat.so\n' "$base" "$base" > "$base/pam/$service"
done
printf 'session required %s/pam-seat.so\n' "$base" >> "$base/pam/seat-test"
printf 'session optional %s/pam-seat.so\nsession required pam_permit.so\n' "$base" >> "$base/pam/seat-optional"
mount --bind "$base/pam" /etc/pam.d
mount -t tmpfs -o mode=755 tmpfs /run
address="unix:abstract=greetd-pam-bus-$$"
printf '%s\n' '<busconfig>' "<listen>$address</listen>" '<auth>EXTERNAL</auth>' \
    '<policy context="default"><allow user="*"/><allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/></policy>' \
    '</busconfig>' > "$base/bus.conf"
bus_pid=$(dbus-daemon --config-file="$base/bus.conf" --fork --print-pid)
export DBUS_SYSTEM_BUS_ADDRESS="$address"
"$2" --seat seat-test --test-only --test-root "$base/fixture-a" \
    --lock-file "$base/fixture-a/lock" --bus-address "$address" \
    --test-direct-node "$base/fixture-a/node" --test-null-device > "$base/daemon-a.log" 2>&1 &
daemon_a=$!
"$2" --seat seat-other --test-only --test-root "$base/fixture-b" \
    --lock-file "$base/fixture-b/lock" --bus-address "$address" \
    --test-direct-node "$base/fixture-b/node" > "$base/daemon-b.log" 2>&1 &
daemon_b=$!
export GREETD_TEST_DAEMON_PID="$daemon_a"
if ! python3 "$5" "$base" "$1" "$base/entry.py" "$base/native-client"; then
    python3 - "$base" <<'PY'
from pathlib import Path
import sys
for path in sorted(Path(sys.argv[1]).glob('*.log')) + sorted(Path(sys.argv[1]).glob('*.stderr')):
    print(f'--- {path.name} ---', file=sys.stderr)
    print(path.read_text(errors='replace'), file=sys.stderr)
PY
    exit 1
fi
