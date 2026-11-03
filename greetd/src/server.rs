use std::{path::Path, rc::Rc};

use nix::unistd::{chown, getpid, Gid, Uid};
use tokio::{
    net::{UnixListener, UnixStream},
    signal::unix::{signal, SignalKind},
    task,
};

use crate::{
    config::{Config, VtSelection},
    context::Context,
    error::Error,
    session::worker::TerminalMode,
    terminal::{self, Terminal},
};
use greetd_ipc::{
    codec::{Error as CodecError, TokioCodec},
    ErrorType, Request, Response,
};

fn reset_vt(term_mode: &TerminalMode) -> Result<(), Error> {
    match term_mode {
        TerminalMode::Terminal { path, vt, .. } => {
            let term = Terminal::open(path)?;
            term.kd_setmode(terminal::KdMode::Text)?;
            term.vt_setactivate(*vt)?;
        }
        TerminalMode::Stdin | TerminalMode::Managed(_) => (),
    }
    Ok(())
}

fn wait_vt(term_mode: &TerminalMode) -> Result<(), Error> {
    match term_mode {
        TerminalMode::Terminal { path, vt, .. } => {
            let term = Terminal::open(path)?;
            term.vt_waitactive(*vt)?;
        }
        TerminalMode::Stdin | TerminalMode::Managed(_) => (),
    }
    Ok(())
}

fn wrap_result<T>(res: Result<T, Error>) -> Response {
    match res {
        Ok(_) => Response::Success,
        Err(Error::AuthError(msg)) => Response::Error {
            error_type: ErrorType::AuthError,
            description: msg,
        },
        Err(e) => Response::Error {
            error_type: ErrorType::Error,
            description: format!("{}", e),
        },
    }
}

async fn client_get_question(ctx: &Context) -> Response {
    match ctx.get_question().await {
        Ok(Some((auth_message_type, auth_message))) => Response::AuthMessage {
            auth_message_type,
            auth_message,
        },
        res => wrap_result(res),
    }
}

async fn client_handler(ctx: &Context, mut s: UnixStream) -> Result<(), Error> {
    loop {
        let req = match Request::read_from(&mut s).await {
            Ok(req) => req,
            Err(CodecError::Eof) => {
                let _ = ctx.cancel().await;
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        let resp = match req {
            Request::CreateSession { username } => match ctx.create_session(username).await {
                Ok(()) => client_get_question(ctx).await,
                res => wrap_result(res),
            },
            Request::PostAuthMessageResponse { response } => {
                match ctx.post_response(response).await {
                    Ok(()) => client_get_question(ctx).await,
                    res => wrap_result(res),
                }
            }
            Request::StartSession { cmd, env } => wrap_result(ctx.start(cmd, env).await),
            Request::CancelSession => wrap_result(ctx.cancel().await),
        };

        if matches!(resp, Response::Error { .. }) {
            let _ = ctx.cancel().await;
        }
        resp.write_to(&mut s).await?;
    }
}

// Return a TTY path and the TTY/VT number, based on the configured target.
//
// If the target is VtSelection::Current, return the path to the TTY
// referenced by stdin and the TTY number it is connected to if possible. If
// the referenced TTY is a PTY, fail. Otherwise, open tty0, get the current VT
// number, and return the path to that TTY and VT.
//
// If the target is VtSelection::Next, open tty0 and request the next VT
// number. Return the TTY and VT
//
// If the target is VtSelection::Specific, simply return the specified TTY and
// VT.
//
// If the target is VtSelection::None, return nothing.
fn get_tty(config: &Config) -> Result<TerminalMode, Error> {
    if let Some(settings) = &config.file.general.multiseat {
        return Ok(TerminalMode::Managed(settings.clone()));
    }
    const TTY_PREFIX: &str = "/dev/tty";
    const PTS_PREFIX: &str = "/dev/pts";

    let term = match config.file.terminal.vt {
        VtSelection::Current => {
            let term = Terminal::stdin();
            match term.ttyname() {
                // We have a usable terminal, so let's decipher and return that
                Ok(term_name)
                    if term_name.starts_with(TTY_PREFIX) && term_name.len() > TTY_PREFIX.len() =>
                {
                    let vt = term_name[TTY_PREFIX.len()..]
                        .parse()
                        .map_err(|e| Error::Error(format!("unable to parse tty number: {}", e)))?;

                    TerminalMode::Terminal {
                        path: term_name,
                        vt,
                        switch: false,
                    }
                }
                Ok(term_name) if term_name.starts_with(PTS_PREFIX) => {
                    return Err("cannot use current VT when started from a psuedo terminal".into())
                }
                // We don't have a usable terminal, so we have to jump through some hoops
                _ => {
                    let sys_term = Terminal::open("/dev/tty0")
                        .map_err(|e| format!("unable to open terminal: {}", e))?;
                    let vt = sys_term
                        .vt_get_current()
                        .map_err(|e| format!("unable to get current VT: {}", e))?;
                    TerminalMode::Terminal {
                        path: format!("/dev/tty{}", vt),
                        vt,
                        switch: false,
                    }
                }
            }
        }
        VtSelection::Next => {
            let term = Terminal::open("/dev/tty0")
                .map_err(|e| format!("unable to open terminal: {}", e))?;
            let vt = term
                .vt_get_next()
                .map_err(|e| format!("unable to get next VT: {}", e))?;
            TerminalMode::Terminal {
                path: format!("/dev/tty{}", vt),
                vt,
                switch: config.file.terminal.switch,
            }
        }
        VtSelection::None => TerminalMode::Stdin,
        VtSelection::Specific(vt) => TerminalMode::Terminal {
            path: format!("/dev/tty{}", vt),
            vt,
            switch: config.file.terminal.switch,
        },
    };
    Ok(term)
}

// Listener is a convenience wrapper for creating the UnixListener we need, and
// for providing cleanup on Drop.
struct Listener(UnixListener, Option<std::fs::File>);

impl Listener {
    fn create(
        uid: Uid,
        gid: Gid,
        settings: Option<&crate::managed::Settings>,
    ) -> Result<(String, Listener), Error> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let (path, lock) = if let Some(settings) = settings {
            std::fs::create_dir_all(&settings.directory)?;
            let metadata = std::fs::symlink_metadata(&settings.directory)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("managed run directory must be root-owned and non-writable".into());
            }
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(format!("{}/controller.lock", settings.directory))?;
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
                return Err("another greetd owns this managed instance".into());
            }
            (format!("{}/greetd.sock", settings.directory), Some(lock))
        } else {
            (format!("/run/greetd-{}.sock", getpid().as_raw()), None)
        };
        let _ = std::fs::remove_file(&path);
        let listener =
            UnixListener::bind(&path).map_err(|e| format!("unable to open listener: {}", e))?;
        chown(path.as_str(), Some(uid), Some(gid))
            .map_err(|e| format!("unable to chown greetd socket at {}: {}", path, e))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok((path, Listener(listener, lock)))
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _lock = &self.1;
        let addr = match self.0.local_addr() {
            Ok(addr) => addr,
            Err(_) => return,
        };
        if let Some(path) = addr.as_pathname() {
            let _ = std::fs::remove_file(path);
        }
    }
}

async fn backend_failed(backend: Option<&crate::managed::Backend>) {
    match backend {
        Some(backend) => backend.failed().await,
        None => std::future::pending().await,
    }
}

pub async fn main(mut config: Config) -> Result<(), Error> {
    let settings = config.file.general.multiseat.clone();
    let available = |name: &str| {
        if let Some(directory) = settings
            .as_ref()
            .and_then(|settings| settings.test_pam_dir.as_ref())
        {
            return Path::new(directory).join(name).is_file();
        }
        Path::new(&format!("/etc/pam.d/{}", name)).exists()
            || Path::new(&format!("/usr/lib/pam.d/{}", name)).exists()
    };
    let service = if available(&config.file.general.service) {
        config.file.general.service.clone()
    } else {
        return Err(format!("PAM '{}' service missing", config.file.general.service).into());
    };

    let greeter_service = if available(&config.file.default_session.service) {
        config.file.default_session.service.clone()
    } else if settings.is_some() {
        return Err("managed greeter PAM service is missing; no user-service fallback".into());
    } else {
        service.clone()
    };
    let owner = if let Some(settings) = &settings {
        if unsafe { libc::geteuid() } != 0 {
            return Err("managed greetd must run as root".into());
        }
        settings.validate_launcher()?;
        Some(crate::managed::Owner::start(settings.clone())?)
    } else {
        None
    };
    let backend = owner.as_ref().map(crate::managed::Owner::backend);

    let u = nix::unistd::User::from_name(&config.file.default_session.user)?.ok_or(format!(
        "configured default session user '{}' not found",
        config.file.default_session.user
    ))?;

    let (listener_path, listener) = Listener::create(u.uid, u.gid, settings.as_ref())?;

    let term_mode = get_tty(&config)?;

    if !config.file.terminal.switch {
        wait_vt(&term_mode).map_err(|e| format!("unable to wait VT: {}", e))?;
    }

    let initial_session = config.file.initial_session.take();
    config.file.general.service = service;
    config.file.default_session.service = greeter_service;
    let ctx = Rc::new(Context::new(
        config.file,
        term_mode.clone(),
        listener_path,
        backend.clone(),
    ));

    if let (Some(s), true) = (initial_session, ctx.is_first_run()) {
        if let Err(e) = ctx.start_user_session(&s.user, vec![s.command]).await {
            eprintln!("unable to start greeter: {}", e);
            reset_vt(&term_mode).map_err(|e| format!("unable to reset VT: {}", e))?;

            return Err(e);
        }
    } else if let Err(e) = ctx.greet().await {
        eprintln!("unable to start greeter: {}", e);
        reset_vt(&term_mode).map_err(|e| format!("unable to reset VT: {}", e))?;

        return Err(e);
    }

    ctx.create_runfile();

    let mut alarm = signal(SignalKind::alarm()).expect("unable to listen for SIGALRM");
    let mut child = signal(SignalKind::child()).expect("unable to listen for SIGCHLD");
    let mut term = signal(SignalKind::terminate()).expect("unable to listen for SIGTERM");
    let mut int = signal(SignalKind::interrupt()).expect("unable to listen for SIGINT");

    let clients = std::sync::Arc::new(tokio::sync::Semaphore::new(32));
    loop {
        tokio::select! {
            _ = backend_failed(backend.as_ref()) => { if let Some(backend) = &backend { backend.stop_workers(); } ctx.terminate().await?; return Err("multiseatd owner or configured seat was lost".into()); }
            _ = child.recv() => ctx.check_children().await.map_err(|e| format!("check_children: {}", e))?,
            _ = alarm.recv() => ctx.alarm().await.map_err(|e| format!("alarm: {}", e))?,
            _ = term.recv() => {
                if let Some(backend) = &backend { backend.stop_workers(); }
                ctx.terminate().await.map_err(|e| format!("terminate: {}", e))?;
                break;
            }
            _ = int.recv() => {
                if let Some(backend) = &backend { backend.stop_workers(); }
                ctx.terminate().await.map_err(|e| format!("terminate: {}", e))?;
                break;
            }
            stream = listener.0.accept() => match stream {
                Ok((stream, _)) => {
                    if settings.is_some() && !matches!(stream.peer_cred()?.uid(), uid if uid == 0 || uid == u.uid.as_raw()) { continue; }
                    let permit = match clients.clone().try_acquire_owned() { Ok(permit) => permit, Err(_) => continue };
                    let client_ctx = ctx.clone();
                    task::spawn_local(async move {
                        let _permit = permit;
                        if let Err(e) = client_handler(&client_ctx, stream).await {
                            if let Err(error) = client_ctx.cancel().await { eprintln!("session cancellation failed: {}", error); }
                            eprintln!("client loop failed: {}", e);
                        }
                    });
                },
                Err(err) => return Err(format!("accept: {}", err).into()),
            }
        }
    }

    Ok(())
}
