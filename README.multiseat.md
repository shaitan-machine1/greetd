# Minimal multiseatd integration

This fork keeps upstream greetd authentication, PAM workers, greeter IPC,
command execution and ordinary child supervision. An opt-in `[multiseatd]`
section delegates device access and VT ownership to multiseatd. Without it,
upstream `[terminal]` behavior is unchanged.

## Configuration

```toml
[general]
service = "greetd"
source_profile = false
runfile = "/run/greetd-seat0-vt7.run"

[multiseatd]
seat = "seat0"
vt = 7

[default_session]
command = "/usr/bin/cage -s -- /usr/bin/regreet"
user = "greeter"
service = "greetd-greeter"
```

`seat` and `vt` are required. VT is a positive number from 1 through 63, or
`"none"` for a non-VT daemon; numeric zero is not configuration syntax. For
example, an independent second controller can use seat="seat1", vt="none" and
runfile="/run/greetd-seat1.run". The VT must belong to the daemon's startup set.
Do not combine `[multiseatd]` with `[terminal]` or `--vt`; use `--config` to
select an instance's configuration. There is no `run_directory` or `--seat`.

Upstream PID-qualified `/run/greetd-<PID>.sock` paths and GREETD_SOCK routing are
retained; Cage forwards that environment to ReGreet. `general.runfile` remains
an empty boot marker controlling `[initial_session]`, not a singleton/PID lock.
Use distinct runfiles for independent instances. No new ReGreet protocol or
runtime-directory discovery is needed.

## Lifecycle and PAM

The privileged, exec'd PAM worker connects to the explicitly configured seat,
pins its root-owned bus owner and creates a fresh context before PAM. Trusted
XDG_SEAT and, when bound, XDG_VTNR/PAM TTY metadata are supplied to PAM. A non-VT
session has no XDG_VTNR or greetd-supplied VT TTY. Greetd does not configure,
attach, switch or reset Linux terminals in this mode.

After overall PAM success, Start grants the final PAM UID and activates the
context. Only the initial VT-backed greeter requests foreground switching.
Replacement greeters and user sessions do not steal foreground. Greeter and
desktop launches receive fresh contexts and the same authority-delivery mechanism.

On completion, cancellation or setup failure, RemoveContext is the sole device
teardown operation. Its checked result is sent before PAM close; no separate ACL
removal/deactivation or main-process cleanup RPC is used. A normal successor
requires positive completed removal. Pending, timeout, daemon owner loss, worker
death or a missing result stops that controller's normal handoff rather than
forcing takeover. Later PAM-close errors are separate from device-removal proof.
To let an uncooperative compositor be killed without losing that proof, the
multiseatd PAM host is not killed alongside its command during escalation.

Greetd has no sessiond dependency, config reader, containment/runtime check,
session ID bookkeeping or session cleanup fallback. PAM policy decides whether
a session-management module is required or optional. Optional module failure
can permit command execution if the overall stack succeeds; it does not guarantee
that a compositor works without its usual runtime directory. Worker death can
leave residual sessions/processes; greetd does not discover or sweep them.

## Authority and FD handling

The trusted configured command receives LIBSEAT_BACKEND=multiseatd and
MULTISEATD_AUTHORITY_FD. Unrelated nonstandard descriptors are close-on-exec;
only this capability is deliberately allowed through. Linux console standard
streams are sanitized; safe supervisor logging/PTY streams may remain. This
Linux integration uses close_range(CLOSE_RANGE_CLOEXEC), requiring Linux 5.11+.

There is no executable allowlist or mandatory wrapper. The entrypoint is trusted
and can duplicate/delegate its capability before consuming it. The maintained
native C libseat backend consumes/unsets authority, closes its copy after getting
a broker connection, and keeps that connection close-on-exec. This prevents
ordinary later exec inheritance on the normal compositor path, not arbitrary
delegation by a trusted launcher. Existing direct FDs and same-UID access are
not generally revoked or isolated by ACL removal.

## Validation

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Run `tests/pam-bus.sh` as the normal build user, supplying:

- MULTISEATD_TEST_BINARY: an explicit non-VT multiseatd test-support executable;
- LIBSEAT_TEST_PREFIX: a maintained native C libseat installation prefix with
  include/libseat.h and lib/libseat.so, built with multiseatd enabled;
- passwordless `sudo -n`, mount namespaces, PAM headers, a C compiler, dbus-daemon,
  busctl, getfacl, Python and standard build tools.

The harness builds unprivileged, then uses private mount/PAM/run namespaces,
a private bus and disposable regular-file ACL fixtures. It never edits host
PAM/services or uses live devices/cgroups. Missing prerequisites return 77.
`test-support` only disables memory locking for this disposable harness; there
is no production runtime bypass. Never ship a test-support build.

Synthetic tests are not physical DRM/input/VT or authenticated graphical-login
acceptance. Those require explicit target-specific deployment and testing.
