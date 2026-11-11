mod config;
mod context;
mod error;
mod managed;
mod pam;
mod scrambler;
mod server;
mod session;
mod terminal;

use crate::{error::Error, session::worker};
use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag},
    sys::mman::{mlockall, MlockAllFlags},
};
use std::os::unix::{
    io::{FromRawFd, RawFd},
    net::UnixDatagram,
};

fn session_worker_main(config: config::Config) -> Result<(), Error> {
    let raw_fd = config.internal.session_worker as RawFd;
    let mut flags = FdFlag::from_bits_retain(fcntl(raw_fd, FcntlArg::F_GETFD)?);
    flags.insert(FdFlag::FD_CLOEXEC);
    fcntl(raw_fd, FcntlArg::F_SETFD(flags))?;
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if config.internal.worker_parent != 0
        && unsafe { libc::getppid() } as u32 != config.internal.worker_parent
    {
        return Err("session controller disappeared before worker startup".into());
    }
    session::managed_worker::set_parent(config.internal.worker_parent);
    let socket = unsafe { UnixDatagram::from_raw_fd(raw_fd) };
    worker::main(&socket)
}
fn run() -> Result<(), Error> {
    libmultiseatd::launch::fill_standard_streams()?;
    let config = config::read_config()?;
    if cfg!(feature = "debug") {
        eprintln!("config: {config:?}");
    }
    if !(cfg!(feature = "test-support") && std::env::var_os("GREETD_TEST_MODE").is_some()) {
        mlockall(MlockAllFlags::all())
            .map_err(|error| format!("unable to lock credential pages: {}", error))?;
    }
    // A PAM host is a distinct exec'd, single-threaded process. It never creates
    // a Tokio runtime or inherits one across PAM/user execution.
    if config.internal.session_worker > 0 {
        return session_worker_main(config);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // Generic startup status, never a context/device policy or RPC fallback.
    // Initial startup and exec'd PAM-host failures propagate as status one;
    // upstream ordinary controller-loop errors log and return zero.
    let started = std::cell::Cell::new(false);
    if let Err(error) =
        runtime.block_on(tokio::task::LocalSet::new().run_until(server::main(config, &started)))
    {
        if !started.get() {
            return Err(error);
        }
        eprintln!("error: {error}");
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", error);
        std::process::exit(1);
    }
}
