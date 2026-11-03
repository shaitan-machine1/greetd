//! Single-threaded, post-exec PAM worker and final trusted launcher boundary.
use super::worker::{ParentToSessionChild, SessionChildToParent, SessionClass};
use crate::{
    error::Error,
    managed::{self, Settings},
    pam::session::PamSession,
};
use libmultiseatd::{launch, Client, Context};
use pam_sys::PamFlag;
use std::{
    collections::BTreeMap,
    ffi::CString,
    os::fd::{AsFd, AsRawFd},
    os::unix::{ffi::OsStrExt, net::UnixDatagram, process::CommandExt},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

static TERMINATED: AtomicBool = AtomicBool::new(false);
static PARENT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
pub fn set_parent(parent: u32) {
    PARENT.store(parent, Ordering::Relaxed);
}
extern "C" fn terminate(_: libc::c_int) {
    TERMINATED.store(true, Ordering::Relaxed);
}
pub fn terminated() -> bool {
    TERMINATED.load(Ordering::Relaxed)
}

pub fn prepare(settings: &Settings, socket: &UnixDatagram) -> Result<(), Error> {
    settings.validate_launcher()?;
    launch::null_standard_streams()?;
    launch::detach_worker()?;
    // No runtime has been created in this exec'd worker. The IPC socket is its
    // only owned nonstandard FD; everything else is inherited raw state.
    unsafe {
        launch::close_unlisted(&[socket.as_raw_fd()])?;
    }
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = terminate as *const () as usize;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
    }
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let parent = PARENT.load(Ordering::Relaxed);
    if parent != 0 && unsafe { libc::getppid() } as u32 != parent {
        return Err("managed controller disappeared".into());
    }
    if managed::session_identity(settings)?.is_some() {
        return Err("managed PAM worker already belongs to a login session".into());
    }
    Ok(())
}

struct Cleanup {
    context: Option<Context>,
    session: Option<String>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(context) = &self.context {
            if let Err(error) = Client::system(Duration::from_secs(2))
                .and_then(|client| client.remove_context_by_id(context.id))
            {
                eprintln!("context cleanup pending: {}", error);
            }
        }
        if let Some(session) = &self.session {
            if let Err(error) = lib_sessiond::bus::Client::system(Duration::from_secs(2))
                .and_then(|client| client.schedule_close_session(session))
            {
                eprintln!("session cleanup pending: {}", error);
            }
        }
    }
}

struct ChildGuard(std::process::Child);
impl std::ops::Deref for ChildGuard {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Only signal an unreaped child-owned process group. Never use a raw
        // PID after reaping, when it could identify an unrelated replacement.
        if self.0.try_wait().is_ok_and(|status| status.is_none()) {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
}

pub fn run(
    socket: &UnixDatagram,
    settings: &Settings,
    class: &SessionClass,
    environment: Vec<String>,
    command: Vec<String>,
    pam: &mut PamSession<'_>,
) -> Result<(), Error> {
    let arguments = settings.arguments(&command)?;
    if environment.len() > 256 {
        return Err("too many session environment variables".into());
    }
    let mut user = nix::unistd::User::from_name(&pam.get_user()?)?.ok_or("PAM user is unknown")?;
    let initial_user = user.name.clone();
    for value in environment
        .iter()
        .filter(|value| managed::allowed_environment(value))
    {
        pam.putenv(value)?;
    }
    for value in [
        format!("XDG_SEAT={}", settings.seat),
        "XDG_SESSION_TYPE=wayland".into(),
        format!("XDG_SESSION_CLASS={}", class.as_str()),
        format!("USER={}", user.name),
        format!("LOGNAME={}", user.name),
        format!("HOME={}", user.dir.display()),
        format!("SHELL={}", user.shell.display()),
    ] {
        pam.putenv(&value)?;
    }
    if let Err(error) = pam.open_session(PamFlag::NONE) {
        // Resolve only actual enclosing containment, not untrusted environment.
        // Never close a pre-existing caller session on a failed PAM open.
        if let Ok(Some(session)) = managed::session_identity(settings) {
            let _ = lib_sessiond::bus::Client::system(Duration::from_secs(2))
                .and_then(|client| client.schedule_close_session(&session));
        }
        return Err(error.into());
    }
    let session = managed::session_identity(settings)?;
    if settings.test_pam_dir.is_none() && session.is_none() {
        return Err("system-login did not establish managed session containment".into());
    }
    SessionChildToParent::ManagedSession {
        session: session.clone(),
    }
    .send(socket)?;
    let mut cleanup = Cleanup {
        context: None,
        session,
    };
    user = nix::unistd::User::from_name(&pam.get_user()?)?.ok_or("final PAM user is unknown")?;
    if user.name != initial_user {
        return Err("PAM identity changed during open_session".into());
    }
    if terminated() {
        return Err("session launch cancelled".into());
    }
    let client = Client::system(Duration::from_secs(11)).map_err(|error| error.to_string())?;
    cleanup.context = Some(
        client
            .create_context(&settings.seat)
            .map_err(|error| error.to_string())?,
    );
    let context = cleanup.context.as_ref().expect("created context");
    SessionChildToParent::ManagedContext {
        context: context.id.to_string(),
        session: cleanup.session.clone(),
    }
    .send(socket)?;
    let mut buffer = [0; 10240];
    match ParentToSessionChild::recv(socket, &mut buffer)? {
        ParentToSessionChild::ManagedAcknowledged => (),
        _ => return Err("managed registration was not acknowledged".into()),
    }
    client
        .grant_access(context.as_fd(), user.uid.as_raw())
        .map_err(|error| error.to_string())?;
    client
        .activate_context(context.as_fd())
        .map_err(|error| error.to_string())?;
    let (seat, terminal) = client
        .seat_metadata(context.as_fd())
        .map_err(|error| error.to_string())?;
    drop(client);
    let list = pam.getenvlist()?;
    let mut env = BTreeMap::new();
    for value in list.to_vec() {
        let value = value.to_string_lossy();
        if let Some((key, value)) = value.split_once('=') {
            if key.starts_with("LD_")
                || key.starts_with("WLR_")
                || matches!(
                    key,
                    "GCONV_PATH"
                        | "LOCPATH"
                        | "NLSPATH"
                        | "GLIBC_TUNABLES"
                        | "BASH_ENV"
                        | "ENV"
                        | "SHELLOPTS"
                        | "BASHOPTS"
                        | "PYTHONPATH"
                        | "PYTHONHOME"
                        | "PERL5OPT"
                        | "PERL5LIB"
                        | "RUBYOPT"
                        | "NODE_OPTIONS"
                        | "DBUS_SYSTEM_BUS_ADDRESS"
                        | "MULTISEATD_AUTHORITY_FD"
                        | "MULTISEATD_CONTEXT_ID"
                        | "SEATD_FD"
                        | "LIBSEAT_BACKEND"
                        | "DISPLAY"
                        | "WAYLAND_DISPLAY"
                        | "WAYLAND_SOCKET"
                        | "XDG_SEAT"
                        | "XDG_VTNR"
                        | "XDG_SESSION_CLASS"
                        | "GREETD_SOCK"
                )
            {
                continue;
            }
            env.insert(key.to_string(), value.to_string());
        }
    }
    env.insert("XDG_SEAT".into(), seat);
    env.insert("XDG_SESSION_TYPE".into(), "wayland".into());
    env.insert("USER".into(), user.name.clone());
    env.insert("LOGNAME".into(), user.name.clone());
    env.insert("HOME".into(), user.dir.to_string_lossy().into_owned());
    env.insert("SHELL".into(), user.shell.to_string_lossy().into_owned());
    if terminal != 0 {
        env.insert("XDG_VTNR".into(), terminal.to_string());
    }
    if let Some(address) = &settings.system_bus {
        env.insert("DBUS_SYSTEM_BUS_ADDRESS".into(), address.clone());
    }
    {
        use std::os::unix::fs::MetadataExt;
        let runtime = env
            .get("XDG_RUNTIME_DIR")
            .ok_or("PAM did not provide XDG_RUNTIME_DIR")?;
        let metadata = std::fs::symlink_metadata(runtime)?;
        if !std::path::Path::new(runtime).is_absolute()
            || !metadata.is_dir()
            || metadata.uid() != user.uid.as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err("PAM runtime directory has unsafe ownership or permissions".into());
        }
    }
    if matches!(class, SessionClass::Greeter) {
        // Never let greeter environment select nested/headless backends which
        // would bypass libseat consumption before Cage execs stock ReGreet.
        env.insert("WLR_BACKENDS".into(), "drm,libinput".into());
        env.insert(
            "GREETD_SOCK".into(),
            format!("{}/greetd.sock", settings.directory),
        );
    }
    if cfg!(feature = "test-support") {
        if let Some(path) = &settings.test_preload {
            env.insert("LD_PRELOAD".into(), path.clone());
        }
        if let Some(path) = &settings.test_library_path {
            env.insert("LD_LIBRARY_PATH".into(), path.clone());
        }
    }
    let raw = context.as_fd().as_raw_fd();
    env.insert("MULTISEATD_AUTHORITY_FD".into(), raw.to_string());
    let username = CString::new(user.name)?;
    let groups: Vec<libc::gid_t> = nix::unistd::getgrouplist(&username, user.gid)?
        .into_iter()
        .map(|group| group.as_raw())
        .collect();
    let directory = CString::new(user.dir.as_os_str().as_bytes())?;
    let uid = user.uid.as_raw();
    let gid = user.gid.as_raw();
    let parent = unsafe { libc::getpid() };
    let mut process = std::process::Command::new(&arguments[0]);
    process.args(&arguments[1..]).env_clear().envs(env);
    // All allocation/NSS/PAM work is complete before fork. Only Linux
    // async-signal-safe setup syscalls run in this callback, then immediate exec.
    unsafe {
        process.pre_exec(move || {
            if libc::setsid() < 0
                || libc::setgroups(groups.len(), groups.as_ptr()) < 0
                || libc::setgid(gid) < 0
                || libc::setuid(uid) < 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) < 0
                || libc::getppid() != parent
                || libc::chdir(directory.as_ptr()) < 0
                || libc::fcntl(raw, libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = ChildGuard(process.spawn()?);
    SessionChildToParent::FinalChildPid(u64::from(child.id())).send(socket)?;
    let mut termination = None;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if terminated() {
            if termination.is_none() {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGTERM);
                }
                termination = Some(std::time::Instant::now());
            } else if termination.is_some_and(|time| time.elapsed() > Duration::from_secs(2)) {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    // Remove access before PAM schedules containment teardown. Parent cleanup
    // independently retains the IDs and handles worker loss through its pidfd.
    if let Some(context) = cleanup.context.take() {
        let _ = Client::system(Duration::from_secs(2))
            .and_then(|client| client.remove_context_by_id(context.id));
    }
    pam.close_session(PamFlag::NONE)?;
    pam.setcred(PamFlag::DELETE_CRED)?;
    pam.end()?;
    cleanup.session = None;
    Ok(())
}
