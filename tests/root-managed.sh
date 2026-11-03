#!/bin/bash
# Private bus, private PAM directory and disposable files only. No live stack.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if (( EUID != 0 )); then
    for tool in cargo cc sudo python3 dbus-daemon gdbus; do command -v "$tool" >/dev/null || exit 77; done
    for variable in MULTISEATD_BINARY WITH_SEAT_BINARY LIBSEAT_SOURCE LIBSEAT_BUILD; do [[ -n ${!variable:-} ]] || { echo "explicit $variable is required" >&2; exit 77; }; done
    sudo -n true || exit 77
    cargo build --manifest-path "$repo/Cargo.toml" --locked -p greetd --features test-support
    build=$(mktemp -d /tmp/greetd-managed-build.XXXXXX)
    trap 'rm -rf "$build"' EXIT
    chmod 755 "$build"
    cc -Wall -Wextra -Werror -fPIC -shared "$repo/tests/fixtures/pam-managed.c" -lpam -o "$build/pam_fixture.so"
    cc -Wall -Wextra -Werror "$repo/tests/fixtures/seat-client.c" -I"$LIBSEAT_SOURCE/include" -L"$LIBSEAT_BUILD" -Wl,-rpath,"$LIBSEAT_BUILD" -lseat -o "$build/seat-client"
    if [[ -n ${CAGE_BINARY:-} && -n ${REGREET_BINARY:-} ]]; then
        cc -Wall -Wextra -Werror -fPIC -shared "$repo/tests/fixtures/headless-session.c" $(pkg-config --cflags --libs wlroots-0.20 wayland-server) -o "$build/headless-session.so"
        cc -Wall -Wextra -Werror "$repo/tests/fixtures/ui-exec.c" -o "$build/ui-exec"
    fi
    sudo -n env CAGE_BINARY="${CAGE_BINARY:-}" REGREET_BINARY="${REGREET_BINARY:-}" LIBSEAT_BUILD="$LIBSEAT_BUILD" MULTISEATD_BINARY="$MULTISEATD_BINARY" WITH_SEAT_BINARY="$WITH_SEAT_BINARY" GREETD_FIXTURE_BUILD="$build" timeout --signal=TERM --kill-after=10s 120s bash "$0" --root
    exit $?
fi
work=$(mktemp -d /tmp/greetd-managed.XXXXXX)
chmod 755 "$work"
cleanup() {
    result=$?
    trap - EXIT
    if (( result )); then for log in "$work"/*.log; do echo "--- $log" >&2; head -c 16000 "$log" >&2; done; fi
    for pid in ${first:-} ${second:-} ${graphical:-} ${daemon:-} ${bus:-}; do kill -TERM "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$work"
    exit "$result"
}
trap cleanup EXIT
cp "$repo/target/debug/greetd" "$work/greetd"
cp "$MULTISEATD_BINARY" "$work/multiseatd"
cp "$WITH_SEAT_BINARY" "$work/with-seat"
cp "$GREETD_FIXTURE_BUILD/seat-client" "$work/seat-client"
cp "$GREETD_FIXTURE_BUILD/pam_fixture.so" "$work/pam_fixture.so"
chmod 755 "$work/greetd" "$work/multiseatd" "$work/with-seat" "$work/seat-client"
mkdir "$work/pam.d" "$work/runtime"
chmod 755 "$work/runtime"
touch "$work/apps.log" "$work/pam.log" "$work/direct"
chmod 666 "$work/apps.log"
chmod 600 "$work/direct"
for service in greetd-test greetd-test-greeter; do
    printf '%s\n' "auth required $work/pam_fixture.so user=nobody" 'account required pam_permit.so' "session required $work/pam_fixture.so trace=$work/pam.log runtime=$work/runtime" >"$work/pam.d/$service"
done
printf '%s\n' '<busconfig>' '<type>system</type>' "<listen>unix:path=$work/bus</listen>" '<auth>EXTERNAL</auth>' '<policy context="default"><allow user="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy>' '<policy user="root"><allow own="*"/></policy>' '</busconfig>' >"$work/bus.conf"
dbus-daemon --nofork --config-file="$work/bus.conf" >"$work/bus.log" 2>&1 & bus=$!
for ((i=0;i<200;i++)); do [[ -S $work/bus ]] && break; sleep .02; done
chmod 666 "$work/bus"
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=$work/bus"
"$work/multiseatd" --test-only --test-seat seat-test --test-seat seat-other --lock-file "$work/multiseat.lock" --test-direct-node "$work/direct" >"$work/multiseat.log" 2>&1 & daemon=$!
for ((i=0;i<200;i++)); do gdbus call --system --dest org.decoupling.multiseatd2 --object-path /org/decoupling/multiseatd2 --method org.decoupling.multiseatd2.Manager.ListSeats >/dev/null 2>&1 && break; sleep .02; done
for seat in seat-test seat-other; do
    printf '%s\n' '[general]' 'service = "greetd-test"' '[multiseat]' "seat = \"$seat\"" "launcher = \"$work/with-seat\"" "run_directory = \"$work/$seat\"" "test_pam_dir = \"$work/pam.d\"" '[default_session]' "command = \"$work/with-seat $work/seat-client greeter $work/apps.log $work/direct\"" 'user = "nobody"' 'service = "greetd-test-greeter"' >"$work/$seat.conf"
done
GREETD_TEST_MODE=1 "$work/greetd" --config "$work/seat-test.conf" >"$work/first.log" 2>&1 & first=$!
GREETD_TEST_MODE=1 "$work/greetd" --config "$work/seat-other.conf" >"$work/second.log" 2>&1 & second=$!
python3 "$repo/tests/managed-flow.py" "$work"
kill -TERM "$first" "$second"
wait "$first"; wait "$second"; unset first second
for ((i=0;i<200;i++)); do
    remaining=$(gdbus call --system --dest org.decoupling.multiseatd2 --object-path /org/decoupling/multiseatd2 --method org.decoupling.multiseatd2.Manager.ListContexts)
    [[ $remaining == '(@a(sssauasbbs) [],)' ]] && break
    sleep .03
done
[[ $remaining == '(@a(sssauasbbs) [],)' ]]
python3 - "$work/pam.log" <<'PY'
import collections, sys
rows = [line.split() for line in open(sys.argv[1])]
opened = collections.Counter(row[1] for row in rows if row[0] == 'open')
closed = collections.Counter(row[1] for row in rows if row[0] == 'close')
assert opened and opened == closed, (opened, closed)
PY
# SIGKILL cannot run PAM close; the parent must still retire context authority
# by pidfd/ID and launch a new independent worker, not reuse the old transport.
baseline=$(wc -l < "$work/apps.log")
GREETD_TEST_MODE=1 "$work/greetd" --config "$work/seat-test.conf" >"$work/worker-loss.log" 2>&1 & first=$!
python3 - "$work" "$baseline" <<'PY'
import os, signal, sys, time
work = sys.argv[1]
def latest():
    lines = list(open(work+'/apps.log'))[int(sys.argv[2]):]
    rows = [line.split() for line in lines if line.startswith('greeter ') and ' seat-test ' in line]
    return rows[-1] if rows else None
for _ in range(500):
    row = latest()
    if row: break
    time.sleep(.02)
else: raise AssertionError('greeter restart did not launch')
os.kill(int(row[2]), signal.SIGKILL)
for _ in range(500):
    new = latest()
    if new and new != row: break
    time.sleep(.02)
else: raise AssertionError('PAM worker loss did not recover')
assert new[1] != row[1] and new[2] != row[2]
PY
kill -TERM "$first"; wait "$first"; unset first
if [[ -n ${CAGE_BINARY:-} && -n ${REGREET_BINARY:-} ]]; then
    cp "$CAGE_BINARY" "$work/cage"
    cp "$REGREET_BINARY" "$work/regreet"
    cp "$GREETD_FIXTURE_BUILD/headless-session.so" "$work/headless-session.so"
    cp "$GREETD_FIXTURE_BUILD/ui-exec" "$work/ui-exec"
    touch "$work/ui.log" "$work/regreet.log"
    chmod 666 "$work/ui.log" "$work/regreet.log"
    cp "$work/seat-test.conf" "$work/graphical.conf"
    python3 - "$work" "$LIBSEAT_BUILD" <<'PY'
import sys
work, library = sys.argv[1:]
path = work+'/graphical.conf'
text = open(path).read().replace('[default_session]', 'test_preload = "'+work+'/headless-session.so"\ntest_library_path = "'+library+'"\n[default_session]')
text = text.replace(work+'/seat-client greeter '+work+'/apps.log '+work+'/direct', work+'/cage -- '+work+'/ui-exec '+work+'/ui.log '+work+'/regreet --logs '+work+'/regreet.log')
open(path, 'w').write(text)
PY
    GREETD_TEST_MODE=1 "$work/greetd" --config "$work/graphical.conf" >"$work/graphical.log" 2>&1 & graphical=$!
    for ((i=0;i<400;i++)); do [[ -s $work/ui.log ]] && break; sleep .03; done
    [[ -s $work/ui.log ]]
    sleep 1
    kill -0 "$graphical"
    # Stock GTK UI must survive startup, not merely the pre-exec probe.
    pgrep -f "^$work/regreet --logs $work/regreet.log" >/dev/null
    kill -TERM "$graphical"; wait "$graphical"; unset graphical
    echo 'Stock Cage/wlroots consumed maintained libseat FD before stock ReGreet exec; no authority/seatd/TTY leak'
fi
# Restart one configured instance, then verify owner loss tears it down.
GREETD_TEST_MODE=1 "$work/greetd" --config "$work/seat-test.conf" >"$work/loss.log" 2>&1 & first=$!
sleep .5
kill -TERM "$daemon"; wait "$daemon"; unset daemon
if wait "$first"; then echo 'managed owner loss must fail greetd' >&2; exit 1; fi
unset first
echo 'Private PAM open/close, worker/authority isolation, per-seat lifecycle and daemon-loss teardown passed'
