//! Trusted launch settings and generic worker supervision. Only the privileged
//! PAM host owns multiseatd capabilities/IDs/RPCs; main has no takeover fallback.
use crate::{error::Error, session::worker::SessionChildToParent};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixDatagram,
    },
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub seat: String,
    pub vt: u32,
    pub directory: String,
    pub system_bus: Option<String>,
    pub test_pam_dir: Option<String>,
    pub test_preload: Option<String>,
    pub test_library_path: Option<String>,
}
impl Settings {
    pub fn instance(&self) -> String {
        format!("{}-vt{}", self.seat, self.vt)
    }
    pub fn socket_path(&self) -> String {
        format!("{}/greetd-{}.sock", self.directory, self.instance())
    }
    pub fn validate(&self) -> Result<(), Error> {
        libmultiseatd::bus_name(&self.seat).map_err(|error| error.to_string())?;
        if self.vt > 63 {
            return Err("managed VT must be 0 or 1..63".into());
        }
        if !Path::new(&self.directory).is_absolute() {
            return Err("managed run directory must be absolute".into());
        }
        if (self.test_pam_dir.is_some()
            || self.test_preload.is_some()
            || self.test_library_path.is_some())
            && !cfg!(feature = "test-support")
        {
            return Err("managed test hooks require test-support".into());
        }
        Ok(())
    }
    pub fn arguments(&self, command: &[String]) -> Result<Vec<String>, Error> {
        let argv = if command.len() == 1 {
            shlex::split(&command[0]).ok_or("invalid managed command quoting")?
        } else {
            command.to_vec()
        };
        if argv.first().is_none_or(String::is_empty) {
            return Err("missing managed command".into());
        }
        Ok(argv)
    }
}
pub fn allowed_environment(value: &str) -> bool {
    let Some((key, value)) = value.split_once('=') else {
        return false;
    };
    !value.contains('\0')
        && value.len() <= 4096
        && (key == "LANG"
            || key.starts_with("LC_")
            || matches!(key, "XDG_CURRENT_DESKTOP" | "DESKTOP_SESSION"))
}

type Outcome = Result<(), String>;
struct Record {
    worker: Arc<OwnedFd>,
    channel: UnixDatagram,
    watching: bool,
    required: bool,
    teardown: Option<Outcome>,
    session: Option<String>,
    final_result: Option<Outcome>,
    released: bool,
    exited: bool,
    exit_drained: bool,
    session_done: bool,
}
struct Shared {
    records: Mutex<BTreeMap<i32, Record>>,
    stop: AtomicBool,
    lost: AtomicBool,
    changed: tokio::sync::watch::Sender<u64>,
}
impl Shared {
    fn changed(&self) {
        self.changed
            .send_modify(|value| *value = value.wrapping_add(1));
    }
    fn fail(&self) {
        self.lost.store(true, Ordering::Release);
        self.changed();
    }
}
#[derive(Clone)]
pub struct Backend(Arc<Shared>);
pub struct Owner {
    backend: Backend,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Backend {
    pub fn track(&self, worker: Arc<OwnedFd>, channel: UnixDatagram) -> Result<(), Error> {
        let mut records = self.0.records.lock().unwrap();
        if self.0.stop.load(Ordering::Acquire) || self.0.lost.load(Ordering::Acquire) {
            return Err("worker supervisor is stopping".into());
        }
        if records.len() >= 64 {
            return Err("worker supervision admission limit reached".into());
        }
        channel.set_nonblocking(true)?;
        records.insert(
            worker.as_raw_fd(),
            Record {
                worker,
                channel,
                watching: false,
                required: false,
                teardown: None,
                session: None,
                final_result: None,
                released: false,
                exited: false,
                exit_drained: false,
                session_done: true,
            },
        );
        Ok(())
    }
    pub fn metadata(&self, worker: &OwnedFd, session: Option<String>) -> Result<(), Error> {
        let mut records = self.0.records.lock().unwrap();
        let record = records
            .get_mut(&worker.as_raw_fd())
            .ok_or("worker registration lost")?;
        if record
            .session
            .as_ref()
            .is_some_and(|old| Some(old) != session.as_ref())
        {
            return Err("worker changed its containment identity".into());
        }
        record.session_done = session.is_none();
        record.session = session;
        Ok(())
    }
    pub fn require_teardown(&self, worker: &OwnedFd) -> Result<(), Error> {
        let mut records = self.0.records.lock().unwrap();
        let record = records
            .get_mut(&worker.as_raw_fd())
            .ok_or("worker registration lost")?;
        if record.teardown.is_some() || record.exited || self.0.lost.load(Ordering::Acquire) {
            return Err("worker is no longer eligible for Start".into());
        }
        record.required = true;
        Ok(())
    }
    pub fn teardown(&self, worker: &OwnedFd, result: Outcome) -> Result<(), Error> {
        let mut records = self.0.records.lock().unwrap();
        let record = records
            .get_mut(&worker.as_raw_fd())
            .ok_or("worker registration lost")?;
        if let Err(error) = apply_teardown(record, result) {
            self.0.fail();
            return Err(error);
        }
        if record.teardown.as_ref().is_some_and(Result::is_err) {
            self.0.fail();
        }
        self.0.changed();
        Ok(())
    }
    pub fn result(&self, worker: &OwnedFd) -> Result<Option<()>, Error> {
        let records = self.0.records.lock().unwrap();
        let record = records
            .get(&worker.as_raw_fd())
            .ok_or("worker registration lost")?;
        match &record.teardown {
            Some(Ok(())) => Ok(Some(())),
            Some(Err(error)) => Err(format!("device teardown failed: {error}").into()),
            None if record.exited && record.required => {
                Err("worker exited without positive device teardown".into())
            }
            None => Ok(None),
        }
    }
    pub fn watch(&self, worker: &OwnedFd) {
        if let Some(record) = self.0.records.lock().unwrap().get_mut(&worker.as_raw_fd()) {
            record.watching = true;
        }
    }
    pub fn release(&self, worker: &OwnedFd) {
        if let Some(record) = self.0.records.lock().unwrap().get_mut(&worker.as_raw_fd()) {
            record.watching = true;
            record.released = true;
        }
    }
    pub fn stop_workers(&self) {
        for record in self.0.records.lock().unwrap().values() {
            signal(&record.worker, libc::SIGTERM);
        }
    }
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.0.changed.subscribe()
    }
    pub async fn failed(&self) {
        let mut changed = self.subscribe();
        while !self.0.lost.load(Ordering::Acquire) {
            if changed.changed().await.is_err() {
                return;
            }
        }
    }
}
fn apply_teardown(record: &mut Record, result: Outcome) -> Result<(), Error> {
    if record.teardown.is_some() {
        return Err("duplicate device teardown result".into());
    }
    record.teardown = Some(result);
    Ok(())
}
struct FailureGuard(Arc<Shared>);
impl Drop for FailureGuard {
    fn drop(&mut self) {
        if !self.0.stop.load(Ordering::Acquire) {
            self.0.fail();
        }
    }
}
impl Owner {
    pub fn start() -> Result<Self, Error> {
        let (changed, _) = tokio::sync::watch::channel(0);
        let shared = Arc::new(Shared {
            records: Mutex::new(BTreeMap::new()),
            stop: AtomicBool::new(false),
            lost: AtomicBool::new(false),
            changed,
        });
        let backend = Backend(shared.clone());
        let thread = std::thread::Builder::new()
            .name("greetd-worker-supervisor".into())
            .spawn(move || {
                let _guard = FailureGuard(shared.clone());
                let mut stopping = None;
                loop {
                    if shared.stop.load(Ordering::Acquire) && stopping.is_none() {
                        stopping = Some(Instant::now() + Duration::from_secs(10));
                    }
                    let mut changed = false;
                    let candidate = {
                        let mut records = shared.records.lock().unwrap();
                        for record in records.values_mut() {
                            let mut drained = false;
                            if record.watching {
                                let mut data = [0; 10240];
                                for _ in 0..32 {
                                    match record.channel.recv(&mut data) {
                                        Ok(length) => {
                                            match serde_json::from_slice::<SessionChildToParent>(
                                                &data[..length],
                                            ) {
                                                Ok(SessionChildToParent::DeviceTeardown {
                                                    result,
                                                }) => {
                                                    if apply_teardown(record, result).is_err() {
                                                        shared.fail();
                                                    }
                                                }
                                                Ok(SessionChildToParent::Finished { result }) => {
                                                    if let Err(error)=&result {eprintln!("PAM host final result (separate from device teardown): {error}");}
                                                    record.session_done |= result.is_ok();
                                                    record.final_result = Some(result);
                                                }
                                                Ok(SessionChildToParent::Error(error)) => {
                                                    record.final_result =
                                                        Some(Err(error.to_string()));
                                                }
                                                Ok(
                                                    SessionChildToParent::Success
                                                    | SessionChildToParent::PamMessage { .. }
                                                    | SessionChildToParent::FinalChildPid(_),
                                                ) => (),
                                                Ok(SessionChildToParent::ManagedSession {
                                                    session,
                                                }) => {
                                                    if record.session.as_ref().is_some_and(|old| {
                                                        Some(old) != session.as_ref()
                                                    }) {
                                                        shared.fail();
                                                    } else {
                                                        record.session_done = session.is_none();
                                                        record.session = session;
                                                    }
                                                }
                                                _ => shared.fail(),
                                            }
                                            changed = true;
                                        }
                                        Err(error)
                                            if error.kind() == std::io::ErrorKind::WouldBlock =>
                                        {
                                            drained = true;
                                            break;
                                        }
                                        Err(error)
                                            if error.kind() == std::io::ErrorKind::Interrupted =>
                                        {
                                            continue
                                        }
                                        Err(_) => {
                                            if !record.exited {
                                                shared.fail();
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                            record.exit_drained = record.exited && drained;
                            let mut poll = libc::pollfd {
                                fd: record.worker.as_raw_fd(),
                                events: libc::POLLIN,
                                revents: 0,
                            };
                            if !record.exited && unsafe { libc::poll(&mut poll, 1, 0) } > 0 {
                                // Drain final datagrams on the next iteration BEFORE
                                // diagnosing missing proof or forgetting the record.
                                record.exited = true;
                                changed = true;
                            } else if record.exit_drained
                                && record.required
                                && record.teardown.is_none()
                            {
                                shared.fail();
                            }
                            if record.teardown.as_ref().is_some_and(Result::is_err) {
                                shared.fail();
                            }
                        }
                        records.retain(|_, record| {
                            !(record.exit_drained
                                && record.released
                                && record.session_done)
                        });
                        records
                            .iter()
                            .find(|(_, record)| record.exited && !record.session_done)
                            .map(|(key, record)| (*key, record.session.clone()))
                    };
                    if changed {
                        shared.changed();
                    }
                    if let Some((key, Some(session))) = candidate {
                        let done = lib_sessiond::bus::Client::system(Duration::from_secs(2))
                            .and_then(|client| client.schedule_close_session(&session))
                            .is_ok();
                        if done {
                            if let Some(record) = shared.records.lock().unwrap().get_mut(&key) {
                                record.session_done = true;
                            }
                        }
                    }
                    if let Some(deadline) = stopping {
                        let records = shared.records.lock().unwrap();
                        if records.is_empty() {
                            break;
                        }
                        if Instant::now() >= deadline {
                            for record in records.values() {
                                signal(&record.worker, libc::SIGKILL);
                            }
                            eprintln!(
                                "generic worker cleanup unresolved for {} workers",
                                records.len()
                            );
                            break;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })?;
        Ok(Self {
            backend,
            thread: Some(thread),
        })
    }
    pub fn backend(&self) -> Backend {
        self.backend.clone()
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.backend.stop_workers();
        self.backend.0.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                eprintln!("worker supervisor panicked");
            }
        }
    }
}

pub fn session_identity(settings: &Settings) -> Result<Option<String>, Error> {
    if settings.test_pam_dir.is_some() && cfg!(feature = "test-support") {
        return Ok(None);
    }
    let path = Path::new("/etc/sessiond.conf");
    let config = if path.exists() {
        lib_sessiond::config::Config::load(path).map_err(|error| error.to_string())?
    } else {
        lib_sessiond::config::Config::default()
    };
    let core = lib_sessiond::SessionCore::new(config).map_err(|error| error.to_string())?;
    Ok(core
        .session_for_process(std::process::id())
        .map_err(|error| error.to_string())?
        .map(|identity| identity.id))
}
pub fn signal(worker: &OwnedFd, signal: i32) {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            worker.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
}
pub fn pidfd(pid: u32) -> Result<Arc<OwnedFd>, Error> {
    use std::os::fd::FromRawFd;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Arc::new(unsafe { OwnedFd::from_raw_fd(raw) }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn greeter_environment_cannot_select_authority_backend_or_loader() {
        for value in [
            "MULTISEATD_AUTHORITY_FD=3",
            "LD_PRELOAD=evil",
            "DBUS_SYSTEM_BUS_ADDRESS=evil",
            "XDG_SEAT=seat-other",
            "XDG_RUNTIME_DIR=/other",
            "WAYLAND_DISPLAY=other",
            "WLR_BACKENDS=headless",
            "BASH_ENV=evil",
        ] {
            assert!(!allowed_environment(value), "{}", value);
        }
        assert!(allowed_environment("LANG=en_US.UTF-8"));
        assert!(allowed_environment("XDG_CURRENT_DESKTOP=weston"));
    }
    fn until(mut ready: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(2);
        while !ready() {
            assert!(Instant::now() < end, "supervision fixture did not settle");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn final_pam_failure_never_erases_positive_device_proof() {
        let owner = Owner::start().unwrap();
        let backend = owner.backend();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let worker = pidfd(child.id()).unwrap();
        let (channel, peer) = UnixDatagram::pair().unwrap();
        backend.track(worker.clone(), channel).unwrap();
        backend.require_teardown(&worker).unwrap();
        backend.watch(&worker);
        assert!(backend.result(&worker).unwrap().is_none());
        SessionChildToParent::DeviceTeardown { result: Ok(()) }
            .send(&peer)
            .unwrap();
        until(|| backend.result(&worker).unwrap().is_some());
        SessionChildToParent::Finished {
            result: Err("injected PAM-close failure".into()),
        }
        .send(&peer)
        .unwrap();
        until(|| {
            backend
                .0
                .records
                .lock()
                .unwrap()
                .get(&worker.as_raw_fd())
                .unwrap()
                .final_result
                .is_some()
        });
        assert!(backend.result(&worker).unwrap().is_some());
        assert!(!backend.0.lost.load(Ordering::Acquire));
        backend.release(&worker);
        drop(owner);
        child.wait().unwrap();
    }
    #[test]
    fn pending_and_dead_without_proof_never_authorize_start() {
        let owner = Owner::start().unwrap();
        let backend = owner.backend();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let worker = pidfd(child.id()).unwrap();
        let (channel, _peer) = UnixDatagram::pair().unwrap();
        backend.track(worker.clone(), channel).unwrap();
        backend.require_teardown(&worker).unwrap();
        backend.watch(&worker);
        assert!(backend.result(&worker).unwrap().is_none());
        signal(&worker, libc::SIGKILL);
        child.wait().unwrap();
        until(|| backend.0.lost.load(Ordering::Acquire));
        assert!(backend.result(&worker).is_err());
        assert!(backend.require_teardown(&worker).is_err());
        backend.release(&worker);
        drop(owner);
    }
    #[test]
    fn explicit_pending_result_is_failure_not_positive_teardown() {
        let owner = Owner::start().unwrap();
        let backend = owner.backend();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let worker = pidfd(child.id()).unwrap();
        let (channel, peer) = UnixDatagram::pair().unwrap();
        backend.track(worker.clone(), channel).unwrap();
        backend.require_teardown(&worker).unwrap();
        backend.watch(&worker);
        SessionChildToParent::DeviceTeardown {
            result: Err("Pending: unfinished withdrawal".into()),
        }
        .send(&peer)
        .unwrap();
        until(|| backend.0.lost.load(Ordering::Acquire));
        assert!(backend.result(&worker).is_err());
        backend.release(&worker);
        drop(owner);
        child.wait().unwrap();
    }
}
