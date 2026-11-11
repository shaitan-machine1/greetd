//! Single-threaded, post-exec PAM worker and final trusted launcher boundary.
use super::worker::{SessionChildToParent, SessionClass};
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
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
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

/// Created before PAM; moved after PamSession construction for strict drop order.
/// This privileged host alone owns the context, pinned client and immutable metadata.
pub struct Host<'a> {
    client: Client,
    context: Option<Context>,
    seat: String,
    vt: u32,
    socket: &'a UnixDatagram,
    reported: Option<Result<(), String>>,
    session: Option<String>,
    activated: bool,
}
fn rpc(error: dbus::Error) -> Error {
    format!("{}: {error}", error.name().unwrap_or("D-Bus error")).into()
}
impl<'a> Host<'a> {
    pub fn new(settings: &Settings, socket: &'a UnixDatagram) -> Result<Self, Error> {
        let client = match &settings.system_bus {
            Some(address) => Client::for_address(address, &settings.seat, Duration::from_secs(10)),
            None => Client::system(&settings.seat),
        }
        .map_err(rpc)?;
        let context = client.create_context(settings.vt).map_err(rpc)?;
        let mut host = Self {
            client,
            context: Some(context),
            seat: String::new(),
            vt: 0,
            socket,
            reported: None,
            session: None,
            activated: false,
        };
        let (seat, vt) = host
            .client
            .seat_metadata(host.context.as_ref().unwrap().as_fd())
            .map_err(rpc)?;
        if seat != settings.seat || vt != settings.vt {
            return Err("immutable seat/VT metadata mismatch".into());
        }
        host.seat = seat;
        host.vt = vt;
        Ok(host)
    }
    pub fn configure_pam(&self, pam: &mut PamSession<'_>) -> Result<(), Error> {
        pam.set_item(
            pam_sys::PamItemType::TTY,
            &if self.vt == 0 {
                String::new()
            } else {
                format!("tty{}", self.vt)
            },
        )?;
        pam.putenv(&format!("XDG_SEAT={}", self.seat))?;
        if self.vt != 0 {
            pam.putenv(&format!("XDG_VTNR={}", self.vt))?;
        } else if pam
            .getenvlist()?
            .to_vec()
            .iter()
            .any(|value| value.to_bytes().starts_with(b"XDG_VTNR="))
        {
            pam.putenv("XDG_VTNR")?;
        }
        Ok(())
    }
    pub fn teardown(&mut self) -> Result<(), Error> {
        if let Some(result) = &self.reported {
            return result.clone().map_err(Error::from);
        }
        let result = self.context.as_ref().map_or(Ok(()), |context| {
            let deactivate = if self.activated {
                self.client.deactivate_context(context.id)
            } else {
                Ok(())
            };
            let remove = self.client.remove_context_by_id(context.id);
            match deactivate {
                Err(error)
                    if !matches!(
                        error.name().and_then(libmultiseatd::ErrorKind::from_name),
                        Some(
                            libmultiseatd::ErrorKind::NotFound
                                | libmultiseatd::ErrorKind::NotAuthorized
                        )
                    ) =>
                {
                    let mut text = rpc(error).to_string();
                    if let Err(error) = remove {
                        text.push_str(&format!("; removal: {}", rpc(error)));
                    }
                    Err(text)
                }
                _ => remove.map_err(|error| rpc(error).to_string()),
            }
        });
        self.reported = Some(result.clone());
        // Explicit RESULT, including failure, precedes every PAM-close path.
        let sent = SessionChildToParent::DeviceTeardown {
            result: result.clone(),
        }
        .send(self.socket);
        if result.is_ok() {
            self.context.take();
        }
        sent?;
        result.map_err(Error::from)
    }
}
impl Drop for Host<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.teardown() {
            eprintln!("device teardown not certified: {error}");
        }
        if let Some(session) = &self.session {
            if let Err(error) = lib_sessiond::bus::Client::system(Duration::from_secs(2))
                .and_then(|client| client.schedule_close_session(session))
            {
                eprintln!("session cleanup pending: {error}");
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
    settings: &Settings,
    class: &SessionClass,
    foreground: bool,
    environment: Vec<String>,
    command: Vec<String>,
    pam: &mut PamSession<'_>,
    host: &mut Host<'_>,
) -> Result<(), Error> {
    let socket = host.socket;
    let arguments = settings.arguments(&command)?;
    settings.validate_command(&arguments)?;
    if environment.len() > 256 {
        return Err("too many session environment variables".into());
    }
    host.configure_pam(pam)?;
    pam.setcred(PamFlag::ESTABLISH_CRED)?;
    let mut user = nix::unistd::User::from_name(&pam.get_user()?)?.ok_or("PAM user is unknown")?;
    let initial_user = (user.name.clone(), user.uid);
    for value in environment
        .iter()
        .filter(|value| managed::allowed_environment(value))
    {
        pam.putenv(value)?;
    }
    for value in [
        "XDG_SESSION_TYPE=wayland".into(),
        format!("XDG_SESSION_CLASS={}", class.as_str()),
        format!("USER={}", user.name),
        format!("LOGNAME={}", user.name),
        format!("HOME={}", user.dir.display()),
        format!("SHELL={}", user.shell.display()),
    ] {
        pam.putenv(&value)?;
    }
    host.configure_pam(pam)?;
    if let Err(error) = pam.open_session(PamFlag::NONE) {
        // Resolve only actual enclosing containment, not untrusted environment.
        // Never close a pre-existing caller session on a failed PAM open.
        if let Ok(Some(session)) = managed::session_identity(settings) {
            host.session = Some(session);
        }
        return Err(error.into());
    }
    let session = managed::session_identity(settings)?;
    if settings.test_pam_dir.is_none() && session.is_none() {
        return Err("system-login did not establish managed session containment".into());
    }
    host.session = session;
    SessionChildToParent::ManagedSession {
        session: host.session.clone(),
    }
    .send(socket)?;
    user = nix::unistd::User::from_name(&pam.get_user()?)?.ok_or("final PAM user is unknown")?;
    if (user.name.clone(), user.uid) != initial_user {
        return Err("PAM identity changed during open_session".into());
    }
    if terminated() {
        return Err("session launch cancelled".into());
    }
    let context = host.context.as_ref().expect("pre-PAM context");
    host.client
        .add_acl_grant(context.as_fd(), user.uid.as_raw())
        .map_err(rpc)?;
    host.client.activate_context(context.id).map_err(rpc)?;
    host.activated = true;
    if foreground && matches!(class, SessionClass::Greeter) && host.vt != 0 {
        host.client.move_to_foreground(context.id).map_err(rpc)?;
    }
    let (seat, terminal) = (host.seat.clone(), host.vt);
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
    env.insert("LIBSEAT_BACKEND".into(), "multiseatd".into());
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
        env.insert("GREETD_SOCK".into(), settings.socket_path());
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
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) < 0
                || libc::setsid() < 0
                || libc::setgroups(groups.len(), groups.as_ptr()) < 0
                || libc::setgid(gid) < 0
                || libc::setuid(uid) < 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
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
    let mut health = std::time::Instant::now();
    let mut dependency_error = None;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if std::time::Instant::now() >= health {
            if let Err(error) = host.client.verify_owner() {
                dependency_error = Some(rpc(error));
                TERMINATED.store(true, Ordering::Relaxed);
            }
            health = std::time::Instant::now() + Duration::from_secs(1);
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
    // Positive proof, not worker exit/Pending, authorizes a successor. PAM's
    // final result remains separate and may arrive after the next normal Start.
    host.teardown()?;
    pam.close_session(PamFlag::NONE)?;
    pam.setcred(PamFlag::DELETE_CRED)?;
    pam.end()?;
    host.session = None;
    if let Some(error) = dependency_error {
        return Err(error);
    }
    Ok(())
}
