//! Explicit multiseatd integration. Blocking clients live in exec workers or
//! this daemon-owned cleanup thread, never hidden inside a client library.
use crate::error::Error;
use libmultiseatd::{Client, ContextId};
use serde::{Deserialize, Serialize};
use std::os::fd::{AsRawFd, OwnedFd};
use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub seat: String,
    pub launcher: String,
    pub entrypoints: Vec<String>,
    pub directory: String,
    pub system_bus: Option<String>,
    pub test_pam_dir: Option<String>,
    pub test_preload: Option<String>,
    pub test_library_path: Option<String>,
}
impl Settings {
    pub fn validate(&self) -> Result<(), Error> {
        if self.seat.len() > 63
            || !self.seat.starts_with("seat")
            || !self
                .seat
                .bytes()
                .skip(4)
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err("invalid multiseat seat name".into());
        }
        if self.entrypoints.len() > 16
            || self
                .entrypoints
                .iter()
                .any(|path| !Path::new(path).is_absolute())
        {
            return Err("at most 16 absolute trusted entrypoints are allowed".into());
        }
        if !Path::new(&self.launcher).is_absolute() || !Path::new(&self.directory).is_absolute() {
            return Err("managed launcher/run directory must be absolute".into());
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
        if argv.is_empty()
            || (argv[0] != self.launcher && !self.entrypoints.contains(&argv[0]))
            || (argv[0] == self.launcher && argv.len() < 2)
        {
            return Err(
                "managed sessions must begin with with-seat or an explicitly trusted entrypoint"
                    .into(),
            );
        }
        Ok(argv)
    }
    pub fn validate_command(&self, arguments: &[String]) -> Result<(), Error> {
        validate_executable(arguments.first().ok_or("missing managed executable")?)
    }
    pub fn validate_launcher(&self) -> Result<(), Error> {
        self.validate()?;
        validate_executable(&self.launcher)?;
        for path in &self.entrypoints {
            if Path::new(path).try_exists()? {
                validate_executable(path)?;
            }
        }
        Ok(())
    }
}
fn validate_executable(path: &str) -> Result<(), Error> {
    use std::path::Component;
    if Path::new(path)
        .components()
        .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err("trusted executable path must not contain dot components".into());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o6022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(
            "trusted executable must be root-owned, executable, non-writable and non-setid".into(),
        );
    }
    for ancestor in Path::new(path).ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err("trusted executable has an unsafe ancestor".into());
        }
    }
    Ok(())
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

struct Record {
    worker: Arc<OwnedFd>,
    context: Option<ContextId>,
    session: Option<String>,
    released: bool,
    final_metadata: bool,
    exited: bool,
    seat_pending: bool,
    seat_done: bool,
    session_done: bool,
    force_session: bool,
}
struct Shared {
    records: Mutex<BTreeMap<i32, Record>>,
    stop: AtomicBool,
    lost: AtomicBool,
    changed: Notify,
}
#[derive(Clone)]
pub struct Backend(Arc<Shared>);
pub struct Owner {
    backend: Backend,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Backend {
    pub fn track(&self, worker: Arc<OwnedFd>) -> Result<(), Error> {
        let mut records = self.0.records.lock().unwrap();
        if records.len() >= 64 {
            return Err("managed cleanup admission limit reached".into());
        }
        records.insert(
            worker.as_raw_fd(),
            Record {
                worker,
                context: None,
                session: None,
                released: false,
                final_metadata: false,
                exited: false,
                seat_pending: false,
                seat_done: true,
                session_done: true,
                force_session: false,
            },
        );
        Ok(())
    }
    pub fn metadata(
        &self,
        worker: &OwnedFd,
        context: Option<ContextId>,
        session: Option<String>,
    ) -> Result<(), Error> {
        let mut records = self.0.records.lock().unwrap();
        let record = records
            .get_mut(&worker.as_raw_fd())
            .ok_or("managed worker registration lost")?;
        if let Some(context) = context {
            if record.context.is_some_and(|old| old != context) {
                return Err("worker changed its registered context".into());
            }
            record.context = Some(context);
            record.seat_done = false;
        }
        if session.is_some() {
            record.session = session;
            record.session_done = false;
        }
        Ok(())
    }
    pub fn final_metadata(&self, worker: &OwnedFd) {
        if let Some(record) = self.0.records.lock().unwrap().get_mut(&worker.as_raw_fd()) {
            record.final_metadata = true;
        }
    }
    pub fn force(&self, worker: &OwnedFd) {
        if let Some(record) = self.0.records.lock().unwrap().get_mut(&worker.as_raw_fd()) {
            record.seat_pending = true;
            record.force_session = true;
        }
    }
    pub fn remove(&self, worker: &OwnedFd) {
        if let Some(record) = self.0.records.lock().unwrap().get_mut(&worker.as_raw_fd()) {
            record.seat_pending = true;
        }
    }
    pub fn release(&self, worker: &OwnedFd) {
        if let Some(record) = self.0.records.lock().unwrap().get_mut(&worker.as_raw_fd()) {
            record.seat_pending = true;
            record.released = true;
        }
    }
    pub fn stop_workers(&self) {
        let workers: Vec<_> = {
            let mut records = self.0.records.lock().unwrap();
            records
                .values_mut()
                .map(|record| {
                    record.seat_pending = true;
                    record.worker.clone()
                })
                .collect()
        };
        for worker in workers {
            signal(&worker, libc::SIGTERM);
        }
    }
    pub async fn failed(&self) {
        loop {
            let changed = self.0.changed.notified();
            if self.0.lost.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}
struct FailureGuard(Arc<Shared>);
impl Drop for FailureGuard {
    fn drop(&mut self) {
        if !self.0.stop.load(Ordering::Acquire) {
            self.0.lost.store(true, Ordering::Release);
            self.0.changed.notify_one();
        }
    }
}
impl Owner {
    pub fn start(settings: Settings) -> Result<Self, Error> {
        let shared = Arc::new(Shared {
            records: Mutex::new(BTreeMap::new()),
            stop: AtomicBool::new(false),
            lost: AtomicBool::new(false),
            changed: Notify::new(),
        });
        let backend = Backend(shared.clone());
        let (ready, started) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("greetd-seat-cleanup".into())
            .spawn(move || {
                let _failure = FailureGuard(shared.clone());
                let setup = (|| -> Result<(Client, String), Error> {
                    let client = Client::system(Duration::from_secs(2))
                        .map_err(|error| error.to_string())?;
                    let owner = client.owner().map_err(|error| error.to_string())?;
                    if !client
                        .list_seats()
                        .map_err(|error| error.to_string())?
                        .iter()
                        .any(|row| row.0 == settings.seat)
                    {
                        return Err("configured multiseat seat is not ready".into());
                    }
                    Ok((client, owner))
                })();
                let (client, owner) = match setup {
                    Ok(value) => {
                        let _ = ready.send(Ok(()));
                        value
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let mut stopping = None;
                let mut cursor = 0usize;
                loop {
                    if shared.stop.load(Ordering::Acquire) && stopping.is_none() {
                        stopping = Some(Instant::now() + Duration::from_secs(10));
                    }
                    if stopping.is_none() {
                        let live = client.owner().ok().as_deref() == Some(owner.as_str())
                            && client
                                .list_seats()
                                .is_ok_and(|rows| rows.iter().any(|row| row.0 == settings.seat));
                        if !live {
                            shared.lost.store(true, Ordering::Release);
                            shared.changed.notify_one();
                        }
                    }
                    let candidate = {
                        let mut records = shared.records.lock().unwrap();
                        for record in records.values_mut() {
                            let mut descriptor = libc::pollfd {
                                fd: record.worker.as_raw_fd(),
                                events: libc::POLLIN,
                                revents: 0,
                            };
                            if unsafe { libc::poll(&mut descriptor, 1, 0) } > 0 {
                                record.exited = true;
                                record.seat_pending = true;
                            }
                            if stopping.is_some() {
                                record.seat_pending = true;
                            }
                        }
                        records.retain(|_, record| {
                            !(record.exited
                                && (record.released || record.final_metadata)
                                && record.seat_done
                                && record.session_done)
                        });
                        let candidates: Vec<_> = records
                            .iter()
                            .filter(|(_, record)| {
                                (record.seat_pending && !record.seat_done)
                                    || ((record.exited
                                        || record.force_session
                                        || stopping.is_some())
                                        && !record.session_done)
                            })
                            .map(|(key, record)| {
                                (
                                    *key,
                                    record.context,
                                    record.session.clone(),
                                    record.seat_pending && !record.seat_done,
                                    (record.exited || record.force_session || stopping.is_some())
                                        && !record.session_done,
                                )
                            })
                            .collect();
                        if candidates.is_empty() {
                            None
                        } else {
                            let candidate = candidates[cursor % candidates.len()].clone();
                            cursor = (cursor + 1) % 64;
                            Some(candidate)
                        }
                    };
                    if let Some((key, context, session, remove, close)) = candidate {
                        let seat_done = !remove
                            || context.is_none_or(|id| client.remove_context_by_id(id).is_ok());
                        let session_done = !close
                            || session.as_ref().is_none_or(|id| {
                                lib_sessiond::bus::Client::system(Duration::from_secs(2))
                                    .and_then(|client| client.schedule_close_session(id))
                                    .is_ok()
                            });
                        let mut records = shared.records.lock().unwrap();
                        if let Some(record) = records.get_mut(&key) {
                            if remove && seat_done {
                                record.seat_done = true;
                            }
                            if close && session_done {
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
                            eprintln!(
                                "managed cleanup still pending for {} workers",
                                records.len()
                            );
                            break;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            })?;
        match started
            .recv()
            .map_err(|error| Error::Error(error.to_string()))
        {
            Ok(Ok(())) => Ok(Self {
                backend,
                thread: Some(thread),
            }),
            result => {
                let _ = thread.join();
                Err(match result {
                    Ok(Err(error)) | Err(error) => error,
                    _ => unreachable!(),
                })
            }
        }
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
                eprintln!("managed cleanup owner panicked");
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
}
