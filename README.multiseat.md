# Managed multiseatd backend

This branch adds an explicit multiseatd v2 backend to greetd 0.10.3. Existing
terminal mode remains separate; managed mode never manages a Linux VT. Requires
multiseat v0.3.0 and the pinned sessiond libraries in `greetd/Cargo.toml`.

Run independent root controllers for each seat with distinct configuration and
run directories. Each controller supports one authenticated user session, then
starts a fresh greeter. No retained-session UI, desktop supervisor, or automatic
cross-seat fallback is provided.

```ini
[general]
service = "greetd"
[multiseat]
seat = "seat0"
run_directory = "/run/greetd-seat0"
launcher = "/usr/libexec/multiseatd/with-seat"
trusted_entrypoints = "/usr/bin/sglogin-weston"
[default_session]
command = "/usr/libexec/multiseatd/with-seat /usr/bin/cage -- /usr/bin/regreet"
user = "greeter"
service = "greetd-greeter"
```

Do not specify a VT or enable profile sourcing. Coordinate multiseatd's explicit
seat0 graphical VT with gettys separately. Run-directory locks use persistent
inodes; never unlink a lock to defeat a running controller. The greeter socket
is mode 0600, owned by its configured account, and authenticates peer UID.

## Trust and lifecycle

Each PAM transaction runs in a distinct exec'd, single-threaded worker, detached
before PAM, with null standard streams and only its private IPC socket. Final
PAM identity determines credentials and grants. Session containment is checked
through existing sessiond APIs, not greeter-provided environment. Missing
containment or an unsafe runtime directory fails closed.

The worker creates and activates a new context before launching the compositor.
It retains authority; the root parent retains registered IDs and pidfds for
independent cleanup. Worker exit, cancellation, failed exec, logout, seat loss,
and multiseatd owner loss retire access. PAM closes schedule existing sessiond
teardown without waiting for it. SIGKILL cannot execute PAM close; registered
session IDs allow the parent to schedule teardown. Permanent kernel/bus failure
can leave reported cleanup pending; there is no durable recovery journal.

Only the configured launcher and explicitly listed absolute trusted entrypoints
may receive full context authority. They and their ancestors must be root-owned
and non-writable (root-owned sticky temporary parents are permitted). Every
entrypoint is trusted with **full** context control and must immediately exec
with-seat at the final compositor boundary. Never prefix it with a shell
profile, logger, dbus-run-session, or unrelated helper inheriting authority.
The packaged Weston entrypoint is one such small trusted launcher.

With-seat closes authority before compositor exec. Cage's maintained C libseat
must consume/unset SEATD_FD and set CLOEXEC before executing stock ReGreet.
Greeter backends are forced to DRM/libinput: a nested backend must not bypass
this consumption. Incoming UI environment cannot select capabilities, loaders,
backends, runtime directories, displays, or trusted bus addresses. Compositor
lineages receive no Linux controlling terminal or terminal descriptors.

## PAM policy

Preserve distribution authentication/account/password policy. Artix's greetd
service includes system-local-login, which includes system-login. Activate
pam_sessiond **once centrally** using loginctl; do not add another entry in
greetd. The greeter uses permit authentication/account policy and the same
central session include, not sessiond's internal user-manager service. Keep
pam_env after the central sessiond integration. Do not run competing runtime
owners such as pam_rundir, pam_elogind or pam_turnstile in this selected stack.
No greetd-specific sessiond module or API is required.

## Local validation

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
# Repeat tests/clippy with --all-features.
```

`tests/root-managed.sh` builds as the normal user, then uses sudo for a private
bus, private PAM configuration/module, and disposable ACL files. It requires
explicit absolute `MULTISEATD_BINARY` (test-support build), `WITH_SEAT_BINARY`,
`LIBSEAT_SOURCE` and `LIBSEAT_BUILD` inputs. Missing prerequisites return 77.
It does not use live PAM configuration, cgroups, console devices or services.

Optionally provide source-built `CAGE_BINARY` and `REGREET_BINARY` to validate
stock Cage 0.3.1 / wlroots 0.20 and stock ReGreet 0.5.0. A test-only preload shim
creates a real wlroots/libseat session and a headless SHM output. An exec probe
checks no authority, seatd descriptor or controlling terminal reaches ReGreet;
the actual unmodified GTK UI then runs. The shim is never packaged. Private PAM
fixtures intentionally bypass sessiond containment: these results do not prove
real cgroup, physical display/input, authenticated graphical-login or reboot
acceptance. No deployment is performed by these tests.
