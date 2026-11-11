# Managed per-seat backend

Managed greetd uses the explicitly routed synchronous multiseatd API. Terminal
mode remains separate; managed greetd never owns Linux terminals or native VT
signals. Run independent root controllers per seat/immutable VT binding.

```ini
[general]
service = "greetd"
[multiseat]
seat = "seat0"
vt = 7
run_directory = "/run/greetd-seat0"
launcher = "/usr/libexec/multiseatd/seat-launch"
trusted_entrypoints = "/usr/bin/sglogin-weston"
[default_session]
command = "/usr/libexec/multiseatd/seat-launch /usr/bin/cage -- /usr/bin/regreet"
user = "greeter"
service = "greetd-greeter"
```

`--seat seat0 --vt 8` overrides managed binding without terminal ownership.
Non-VT seats use zero. Instance locks, sockets and run markers include **seat and
VT**, even in a shared run directory. For the example, the socket is
`/run/greetd-seat0/greetd-seat0-vt7.sock`. Locks use persistent inodes; never unlink
a live lock. Socket mode is 0600 with peer-UID authorization. Coordinate all
multiseatd VT reservations/gettys and preserve independent recovery first.
Do not enable terminal management or profile sourcing in managed mode.

## Ownership and lifecycle

Every PAM transaction has a distinct exec'd single-threaded privileged **host**.
Before PAM starts it creates its context and verifies immutable seat/VT metadata.
PAM receives that seat, VT environment and TTY name without opening a terminal.
Credentials and PAM open occur on Start, not during parallel authentication.
Final verified PAM identity determines UID grants. Containment/runtime directory
checks use existing sessiond/PAM contracts, not greeter-provided environment.

The host alone owns the context authority, ID and pinned multiseatd client. It
activates by root ID after PAM open, foregrounds **only the controller's initial
greeter**, and launches the compositor lineage. No foreground sampling or binding
changes occur during authentication. Other seats/VTs and background active
contexts remain independent. Main performs generic worker/pidfd supervision;
it stores no context IDs and issues no multiseatd cleanup/takeover RPCs.

On logout/cancellation/error, the host deactivates/removes its context, determines
actual device teardown and sends
an explicit **result before PAM close**. Drop ordering preserves this boundary on
unwind, including authentication/exec failure. Only positive teardown authorizes
a next normal Start. Pending, timeout, failure or worker death without that result
stops the controller; authority EOF cleanup is not positive proof and does not
permit forced takeover. Final PAM/worker outcomes are handled separately: an
old PAM close may still be running after a certified normal handoff, and its
failure does not erase successful device proof. Generic sessiond teardown
scheduling on worker loss preserves the existing session boundary.

Each controller supports one authenticated user compositor, then a fresh greeter.
No retained-session UI, desktop supervisor or automatic cross-seat fallback exists.

## Trusted exec boundary

Only the configured launcher and explicitly trusted absolute entrypoints may
receive full authority. Files/ancestors must be root-owned and non-writable
(root-owned sticky temporary parents are allowed). Entrypoints must immediately
exec seat-launch at the final compositor boundary. Never prefix them with a
shell profile, logger, dbus-run-session or other helper inheriting authority.
Fork setup marks every nonstandard FD CLOEXEC before explicitly allowing the
one authority FD; SDK/PAM/IPC descriptors do not survive exec. A native trusted
entrypoint receives explicit `LIBSEAT_BACKEND=multiseatd` and consumes its authority
during libseat open; pre-open loaders/helpers are trusted with full authority.
Strict seat-launch overrides this with `seatd` and a fresh inherited endpoint.

Seat-launch closes full authority before compositor exec. Cage's maintained C
libseat consumes/unsets SEATD_FD and sets CLOEXEC before stock ReGreet exec.
Greeters are forced to DRM/libinput rather than an environment-selected nested
backend. UI environment cannot select capabilities, loaders, trusted buses,
runtime directories or backends. Ordinary applications receive neither authority
nor seatd FDs; compositor lineages receive no Linux controlling terminal/VT FD.

## PAM policy

Preserve distribution authentication/account/password policy. Artix greetd
includes system-local-login/system-login; activate pam_sessiond **once centrally**
using loginctl, not again in greetd. Greeters use permit auth/account and the same
central session include, not sessiond's internal user-manager service. Keep
pam_env after central sessiond integration. Do not run competing runtime owners
(pam_rundir/pam_elogind/pam_turnstile). No greetd-specific sessiond API/module exists.

## Validation

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
# Repeat tests/clippy with --all-features.
```

`tests/root-managed.sh` builds as the normal user, then uses sudo only for private
buses/PAM configuration and disposable ACL files. Supply explicit absolute
`MULTISEATD_BINARY` (non-VT test-support build), `SEAT_LAUNCH_BINARY`,
`LIBSEAT_SOURCE` and `LIBSEAT_BUILD`. Repeat with `GREETD_NATIVE=1` and a
native-enabled libseat build to exercise the native launch boundary. An optional
explicit `GREETD_CARGO_CONFIG`
selects caller-supplied Cargo dependency overrides. Missing prerequisites return
77. No host PAM, cgroups, console devices or services are changed.

The harness checks pre-auth immutable metadata/rejection, final identity, actual
temporary-file ACLs, detached FD hygiene, two-seat isolation, positive handoff
while old PAM close is delayed, and refusal of worker-death takeover. Generic
supervisor unit tests separately cover Pending and late final PAM failure.

Optional explicit `CAGE_BINARY`/`REGREET_BINARY` exercise stock Cage 0.3.1 / wlroots
0.20 and stock ReGreet 0.5.0 using a test-only headless preload shim. The shim
is never packaged. These fixtures bypass real sessiond containment and establish
neither real native VT/device revocation, authenticated graphical login nor
physical display/input or reboot acceptance. No deployment is performed here.
