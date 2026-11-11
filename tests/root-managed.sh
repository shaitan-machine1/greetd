#!/bin/bash
# Private bus, private PAM directory and disposable files only. No live stack.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if (( EUID != 0 )); then
    for tool in cargo cc sudo python3 dbus-daemon gdbus; do command -v "$tool" >/dev/null || exit 77; done
    for variable in MULTISEATD_BINARY SEAT_LAUNCH_BINARY LIBSEAT_SOURCE LIBSEAT_BUILD; do [[ -n ${!variable:-} ]] || { echo "explicit $variable is required" >&2; exit 77; }; done
    sudo -n true || exit 77
    extra=(); if [[ -n ${GREETD_CARGO_CONFIG:-} ]]; then extra+=(--config "$GREETD_CARGO_CONFIG"); fi
    cargo build --manifest-path "$repo/Cargo.toml" "${extra[@]}" --locked -p greetd --features test-support
    build=$(mktemp -d /tmp/greetd-managed-build.XXXXXX)
    trap 'rm -rf "$build"' EXIT
    chmod 755 "$build"
    cc -Wall -Wextra -Werror -fPIC -shared "$repo/tests/fixtures/pam-managed.c" -lpam -o "$build/pam_fixture.so"
    cc -Wall -Wextra -Werror "$repo/tests/fixtures/seat-client.c" -I"$LIBSEAT_SOURCE/include" -L"$LIBSEAT_BUILD" -Wl,-rpath,"$LIBSEAT_BUILD" -lseat -o "$build/seat-client"
    if [[ -n ${CAGE_BINARY:-} && -n ${REGREET_BINARY:-} ]]; then
        cc -Wall -Wextra -Werror -fPIC -shared "$repo/tests/fixtures/headless-session.c" $(pkg-config --cflags --libs wlroots-0.20 wayland-server) -o "$build/headless-session.so"
        cc -Wall -Wextra -Werror "$repo/tests/fixtures/ui-exec.c" -o "$build/ui-exec"
    fi
    sudo -n env GREETD_NATIVE="${GREETD_NATIVE:-0}" CAGE_BINARY="${CAGE_BINARY:-}" REGREET_BINARY="${REGREET_BINARY:-}" LIBSEAT_BUILD="$LIBSEAT_BUILD" MULTISEATD_BINARY="$MULTISEATD_BINARY" SEAT_LAUNCH_BINARY="$SEAT_LAUNCH_BINARY" GREETD_FIXTURE_BUILD="$build" timeout --signal=TERM --kill-after=10s 150s bash "$0" --root
    exit $?
fi
work=$(mktemp -d /tmp/greetd-managed.XXXXXX)
chmod 755 "$work"
cleanup() {
    result=$?; trap - EXIT
    if (( result )); then for log in "$work"/*.log; do echo "--- $log" >&2; head -c 16000 "$log" >&2; done; fi
    for pid in ${first:-} ${second:-} ${graphical:-} ${daemon:-} ${other_daemon:-} ${bus:-}; do kill -TERM "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$work"; exit "$result"
}
trap cleanup EXIT
cp "$repo/target/debug/greetd" "$work/greetd"
cp "$MULTISEATD_BINARY" "$work/multiseatd"
cp "$SEAT_LAUNCH_BINARY" "$work/seat-launch"
cp "$GREETD_FIXTURE_BUILD/seat-client" "$work/seat-client"
cp "$GREETD_FIXTURE_BUILD/pam_fixture.so" "$work/pam_fixture.so"
chmod 755 "$work/greetd" "$work/multiseatd" "$work/seat-launch" "$work/seat-client"
mkdir "$work/pam.d" "$work/runtime" "$work/fixtures"
chmod 755 "$work/runtime"
touch "$work/apps.log" "$work/pam.log"; chmod 666 "$work/apps.log"
for service in greetd-test greetd-test-greeter; do
    printf '%s\n' "auth required $work/pam_fixture.so user=nobody trace=$work/pam.log" 'account required pam_permit.so' "session required $work/pam_fixture.so trace=$work/pam.log runtime=$work/runtime" >"$work/pam.d/$service"
done
printf '%s\n' '<busconfig>' '<type>system</type>' "<listen>unix:path=$work/bus</listen>" '<auth>EXTERNAL</auth>' '<policy context="default"><allow user="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy>' '<policy user="root"><allow own="*"/></policy>' '</busconfig>' >"$work/bus.conf"
dbus-daemon --nofork --config-file="$work/bus.conf" >"$work/bus.log" 2>&1 & bus=$!
for ((i=0;i<200;i++)); do [[ -S $work/bus ]] && break; sleep .02; done
chmod 666 "$work/bus"; export DBUS_SYSTEM_BUS_ADDRESS="unix:path=$work/bus"
contexts() { gdbus call --system --dest "org.SGLogin.Multiseatd1.Seat_seat_2d$1" --object-path /org/SGLogin/Multiseatd1 --method org.SGLogin.Multiseatd1.Manager.ListContexts; }
compositor="$work/seat-launch $work/seat-client"
if [[ ${GREETD_NATIVE:-0} == 1 ]]; then compositor="$work/seat-client"; fi
for seat in seat-test seat-other; do
    mkdir -m 700 "$work/fixtures/$seat"; touch "$work/fixtures/$seat/direct"; chmod 600 "$work/fixtures/$seat/direct"
    "$work/multiseatd" --seat "$seat" --test-only --test-root "$work/fixtures/$seat" --lock-file "$work/fixtures/$seat/daemon.lock" --bus-address "$DBUS_SYSTEM_BUS_ADDRESS" --test-direct-node "$work/fixtures/$seat/direct" >"$work/$seat-daemon.log" 2>&1 &
    if [[ $seat == seat-test ]]; then daemon=$!; else other_daemon=$!; fi
    for ((i=0;i<200;i++)); do contexts "${seat#seat-}" >/dev/null 2>&1 && break; sleep .02; done
    contexts "${seat#seat-}" >/dev/null
    # After private startup validation, expose traversal ONLY on this disposable
    # root-owned directory so UID ACL access can be exercised by the app. It
    # remains non-writable; production paths/devices are never involved.
    chmod 711 "$work/fixtures/$seat"
    printf '%s\n' '[general]' 'service = "greetd-test"' '[multiseat]' "seat = \"$seat\"" 'vt = 0' "launcher = \"$work/seat-launch\"" "trusted_entrypoints = \"$work/seat-client\"" "run_directory = \"$work/$seat\"" "test_pam_dir = \"$work/pam.d\"" '[default_session]' "command = \"$compositor greeter $work/apps.log $work/fixtures/$seat/direct\"" 'user = "nobody"' 'service = "greetd-test-greeter"' >"$work/$seat.conf"
done
# A non-VT binding rejection must occur before PAM authentication/session open.
if GREETD_TEST_MODE=1 "$work/greetd" --config "$work/seat-test.conf" --seat seat-test --vt 7 >"$work/binding.log" 2>&1; then echo 'invalid immutable binding was accepted' >&2; exit 1; fi
[[ ! -s $work/pam.log ]]
GREETD_TEST_MODE=1 "$work/greetd" --config "$work/seat-test.conf" >"$work/first.log" 2>&1 & first=$!
GREETD_TEST_MODE=1 "$work/greetd" --config "$work/seat-other.conf" >"$work/second.log" 2>&1 & second=$!
python3 "$repo/tests/managed-flow.py" "$work"
kill -TERM "$first" "$second"; wait "$first"; wait "$second"; unset first second
for seat in test other; do
    for ((i=0;i<200;i++)); do remaining=$(contexts "$seat"); [[ $remaining == '(@a(suauaubbb) [],)' ]] && break; sleep .03; done
    [[ $remaining == '(@a(suauaubbb) [],)' ]]
done
python3 - "$work/pam.log" <<'PY'
import collections, sys
rows = [line.split() for line in open(sys.argv[1])]
opened = collections.Counter(row[1] for row in rows if row[0] == 'open')
closed = collections.Counter(row[1] for row in rows if row[0] == 'close')
assert opened and opened == closed, (opened, closed)
PY
# Preserve upstream unexpected-greeter lifecycle, not managed-only respawn.
# A successful teardown with no scheduled user exits/logs the runtime error;
# upstream top-level controller errors return zero, unlike initial-start failure.
baseline=$(wc -l < "$work/apps.log")
GREETD_TEST_MODE=1 "$work/greetd" --config "$work/seat-test.conf" >"$work/greeter-exit.log" 2>&1 & first=$!
python3 - "$work" "$baseline" <<'PY'
import os, signal, sys, time
path=sys.argv[1]+'/apps.log'; baseline=int(sys.argv[2])
for _ in range(500):
    rows=[line.split() for line in list(open(path))[baseline:] if line.startswith('greeter ')]
    if rows: break
    time.sleep(.02)
else: raise AssertionError('greeter did not launch')
os.kill(int(rows[0][1]),signal.SIGTERM)
time.sleep(1)
assert len(list(open(path))[baseline:])==1, 'unexpected greeter exit respawned in main'
PY
wait "$first"; unset first
grep -q 'greeter exited without creating a session' "$work/greeter-exit.log"
# Worker death without positive proof MUST NOT authorize a normal replacement.
baseline=$(wc -l < "$work/apps.log")
GREETD_TEST_MODE=1 "$work/greetd" --config "$work/seat-test.conf" >"$work/worker-loss.log" 2>&1 & first=$!
python3 - "$work" "$baseline" <<'PY'
import os, signal, sys, time
work = sys.argv[1]
def latest():
    rows = [line.split() for line in list(open(work+'/apps.log'))[int(sys.argv[2]):] if line.startswith('greeter ') and ' seat-test ' in line]
    return rows[-1] if rows else None
for _ in range(500):
    row = latest()
    if row: break
    time.sleep(.02)
else: raise AssertionError('greeter did not launch')
os.kill(int(row[2]), signal.SIGKILL)
time.sleep(1)
assert latest() == row, 'worker death incorrectly authorized forced takeover'
PY
wait "$first"; unset first
grep -q 'error:' "$work/worker-loss.log"
if [[ -n ${CAGE_BINARY:-} && -n ${REGREET_BINARY:-} ]]; then
    cp "$CAGE_BINARY" "$work/cage"; cp "$REGREET_BINARY" "$work/regreet"
    cp "$GREETD_FIXTURE_BUILD/headless-session.so" "$work/headless-session.so"
    cp "$GREETD_FIXTURE_BUILD/ui-exec" "$work/ui-exec"
    touch "$work/ui.log" "$work/regreet.log"; chmod 666 "$work/ui.log" "$work/regreet.log"
    cp "$work/seat-test.conf" "$work/graphical.conf"
    python3 - "$work" "$LIBSEAT_BUILD" <<'PY'
import sys
work, library = sys.argv[1:]
path = work+'/graphical.conf'
text = open(path).read().replace('[default_session]', 'test_preload = "'+work+'/headless-session.so"\ntest_library_path = "'+library+'"\n[default_session]')
text = text.replace(work+'/seat-client greeter '+work+'/apps.log '+work+'/fixtures/seat-test/direct', work+'/cage -- '+work+'/ui-exec '+work+'/ui.log '+work+'/regreet --logs '+work+'/regreet.log')
text = text.replace('trusted_entrypoints = "'+work+'/seat-client"', 'trusted_entrypoints = "'+work+'/seat-client '+work+'/cage"')
open(path, 'w').write(text)
PY
    GREETD_TEST_MODE=1 "$work/greetd" --config "$work/graphical.conf" >"$work/graphical.log" 2>&1 & graphical=$!
    for ((i=0;i<400;i++)); do [[ -s $work/ui.log ]] && break; sleep .03; done
    [[ -s $work/ui.log ]]; sleep 1; kill -0 "$graphical"
    pgrep -f "^$work/regreet --logs $work/regreet.log" >/dev/null
    kill -TERM "$graphical"; wait "$graphical"; unset graphical
    echo 'Stock Cage/wlroots consumed maintained libseat FD before stock ReGreet exec; no authority/seatd/TTY leak'
fi
GREETD_TEST_MODE=1 "$work/greetd" --config "$work/seat-test.conf" >"$work/loss.log" 2>&1 & first=$!
sleep .5; kill -TERM "$daemon"; wait "$daemon"; unset daemon
wait "$first"; unset first
grep -q 'error:' "$work/loss.log"
echo 'Private PAM metadata, positive pre-close handoff, separate worker outcomes, per-seat isolation and no unconfirmed takeover passed'
