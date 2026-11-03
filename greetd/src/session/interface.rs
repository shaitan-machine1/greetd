use std::{
    os::fd::OwnedFd,
    os::unix::process::CommandExt,
    os::unix::{io::AsRawFd, net::UnixDatagram},
    sync::Arc,
};

use nix::{sys::signal::Signal, unistd::Pid};

use async_trait::async_trait;

use tokio::net::UnixDatagram as TokioUnixDatagram;

use super::worker::{AuthMessageType, ParentToSessionChild, SessionChildToParent};
use crate::{error::Error, scrambler::Scrambler};

#[async_trait]
trait AsyncRecv<T: Sized> {
    async fn recv(sock: &mut TokioUnixDatagram) -> Result<T, Error>;
}

#[async_trait]
trait AsyncSend {
    async fn send(&self, sock: &mut TokioUnixDatagram) -> Result<(), Error>;
}

#[async_trait]
impl<'a> AsyncSend for ParentToSessionChild<'a> {
    async fn send(&self, sock: &mut TokioUnixDatagram) -> Result<(), Error> {
        let mut out =
            serde_json::to_vec(self).map_err(|e| format!("unable to serialize message: {}", e))?;
        if out.len() > 10240 {
            out.scramble();
            return Err("session worker request exceeded its bounded frame".into());
        }
        sock.send(&out)
            .await
            .map_err(|e| format!("unable to send message: {}", e))?;
        out.scramble();
        Ok(())
    }
}

#[async_trait]
impl AsyncRecv<SessionChildToParent> for SessionChildToParent {
    async fn recv(sock: &mut TokioUnixDatagram) -> Result<SessionChildToParent, Error> {
        let mut data = [0; 10240];
        let len = sock
            .recv(&mut data[..])
            .await
            .map_err(|e| format!("unable to recieve message: {}", e))?;
        let msg = serde_json::from_slice(&data[..len])
            .map_err(|e| format!("unable to deserialize message: {}", e))?;
        Ok(msg)
    }
}

/// SessionChild tracks the processes spawned by a session
pub struct SessionChild {
    pub task: Pid,
    pub sub_task: Pid,
    managed: Option<(crate::managed::Backend, Arc<OwnedFd>)>,
}

impl SessionChild {
    /// Check if this session has this pid.
    pub fn owns_pid(&self, pid: Pid) -> bool {
        self.task == pid
    }

    /// Send SIGTERM to the session child.
    pub fn term(&self) {
        if let Some((backend, worker)) = &self.managed {
            backend.remove(worker);
            crate::managed::signal(worker, libc::SIGTERM);
        } else {
            let _ = nix::sys::signal::kill(self.sub_task, Signal::SIGTERM);
        }
    }

    /// Send SIGKILL to the session child.
    pub fn kill(&self) {
        if let Some((backend, worker)) = &self.managed {
            backend.force(worker);
            crate::managed::signal(worker, libc::SIGTERM);
        } else {
            let _ = nix::sys::signal::kill(self.sub_task, Signal::SIGKILL);
            let _ = nix::sys::signal::kill(self.task, Signal::SIGKILL);
        }
    }
}

impl Drop for SessionChild {
    fn drop(&mut self) {
        if let Some((backend, worker)) = &self.managed {
            backend.release(worker);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.started {
            if let Some((backend, worker)) = &self.managed {
                backend.release(worker);
                crate::managed::signal(worker, libc::SIGTERM);
            } else {
                let _ = nix::sys::signal::kill(self.task, Signal::SIGTERM);
            }
        }
    }
}

#[derive(Debug)]
pub enum SessionState {
    Question(AuthMessageType, String),
    Ready,
}

/// A device to initiate a logged in PAM session.
pub struct Session {
    managed: Option<(crate::managed::Backend, Arc<OwnedFd>)>,
    started: bool,
    task: Pid,
    sock: TokioUnixDatagram,
    last_msg: Option<SessionChildToParent>,
}

impl Session {
    /// Create a session started as an external process.
    pub fn new_external(backend: Option<crate::managed::Backend>) -> Result<Session, Error> {
        // Pipe used to communicate the true PID of the final child.
        let (parentfd, childfd) =
            UnixDatagram::pair().map_err(|e| format!("could not create pipe: {}", e))?;

        parentfd.set_nonblocking(true)?;
        let parentfd = TokioUnixDatagram::from_std(parentfd)?;
        let raw_child = childfd.as_raw_fd();
        let mut process = std::process::Command::new(std::env::current_exe()?);
        process.args([
            "--session-worker",
            &raw_child.to_string(),
            "--worker-parent",
            &std::process::id().to_string(),
        ]);
        unsafe {
            process.pre_exec(move || {
                let flags = libc::fcntl(raw_child, libc::F_GETFD);
                if flags < 0 || libc::fcntl(raw_child, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = process.spawn()?;
        let child = Pid::from_raw(child.id() as i32);
        let managed = if let Some(backend) = backend {
            let descriptor = crate::managed::pidfd(child.as_raw() as u32).inspect_err(|_| {
                let _ = nix::sys::signal::kill(child, Signal::SIGTERM);
            })?;
            if let Err(error) = backend.track(descriptor.clone()) {
                crate::managed::signal(&descriptor, libc::SIGTERM);
                return Err(error);
            }
            Some((backend, descriptor))
        } else {
            None
        };
        Ok(Session {
            managed,
            started: false,
            task: child,
            sock: parentfd,
            last_msg: None,
        })
    }

    async fn receive(&mut self) -> Result<SessionChildToParent, Error> {
        if let Some((_, worker)) = &self.managed {
            let descriptor = worker.try_clone()?;
            let watched = unsafe { tokio::io::unix::AsyncFd::register(descriptor) }
                .map_err(std::io::Error::from)?;
            tokio::select! {
                biased;
                message = SessionChildToParent::recv(&mut self.sock) => message,
                ready = watched.readable() => {
                    let _ready = ready?;
                    let mut data = [0; 10240];
                    match self.sock.try_recv(&mut data) {
                        Ok(length) => Ok(serde_json::from_slice(&data[..length])?),
                        Err(_) => Err("managed PAM worker exited".into()),
                    }
                }
            }
        } else {
            SessionChildToParent::recv(&mut self.sock).await
        }
    }

    /// Initiates the session, which will cause authentication to begin.
    pub async fn initiate(&mut self, msg: ParentToSessionChild<'_>) -> Result<(), Error> {
        msg.send(&mut self.sock).await?;
        Ok(())
    }

    /// Return the current state of this session.
    pub async fn get_state(&mut self) -> Result<SessionState, Error> {
        let msg = match self.last_msg.take() {
            Some(msg) => msg,
            None => self.receive().await?,
        };

        self.last_msg = Some(msg.clone());

        match msg {
            SessionChildToParent::PamMessage { style, msg } => {
                Ok(SessionState::Question(style, msg))
            }
            SessionChildToParent::Success => Ok(SessionState::Ready),
            SessionChildToParent::Error(e) => Err(e),
            msg => panic!(
                "expected PamMessage, Success or Error from session worker, got: {:?}",
                msg
            ),
        }
    }

    /// Cancel the session.
    pub async fn cancel(&mut self) -> Result<(), Error> {
        self.last_msg = None;
        if let Some((backend, worker)) = &self.managed {
            backend.remove(worker);
            crate::managed::signal(worker, libc::SIGTERM);
            return Ok(());
        }
        ParentToSessionChild::Cancel.send(&mut self.sock).await?;
        Ok(())
    }

    /// Send a response to an authentication question, or None to cancel the
    /// authentication attempt.
    pub async fn post_response(&mut self, answer: Option<String>) -> Result<(), Error> {
        self.last_msg = None;
        let r = ParentToSessionChild::PamResponse { resp: answer };
        r.send(&mut self.sock).await?;
        if let ParentToSessionChild::PamResponse {
            resp: Some(mut resp),
        } = r
        {
            resp.scramble();
        }
        Ok(())
    }

    ///
    /// Send the arguments that will be used to start the session.
    ///
    pub async fn send_args(&mut self, cmd: Vec<String>, env: Vec<String>) -> Result<(), Error> {
        let msg = ParentToSessionChild::Args { env, cmd };
        msg.send(&mut self.sock).await?;

        let msg = self.receive().await?;

        self.last_msg = Some(msg.clone());

        match msg {
            SessionChildToParent::Success => Ok(()),
            SessionChildToParent::Error(e) => Err(e),
            msg => panic!(
                "expected Success or Error from session worker, got: {:?}",
                msg
            ),
        }
    }

    ///
    /// Start the session.
    ///
    pub async fn start(&mut self) -> Result<SessionChild, Error> {
        let msg = ParentToSessionChild::Start;
        msg.send(&mut self.sock).await?;

        let sub_task = loop {
            match self.receive().await? {
                SessionChildToParent::Error(e) => return Err(e),
                SessionChildToParent::ManagedSession { session } => {
                    let (backend, worker) =
                        self.managed.as_ref().ok_or("unexpected managed metadata")?;
                    backend.metadata(worker, None, session)?;
                }
                SessionChildToParent::ManagedContext { context, session } => {
                    let (backend, worker) =
                        self.managed.as_ref().ok_or("unexpected managed context")?;
                    let context = context
                        .parse::<libmultiseatd::ContextId>()
                        .map_err(|error| error.to_string())?;
                    backend.metadata(worker, Some(context), session)?;
                    ParentToSessionChild::ManagedAcknowledged
                        .send(&mut self.sock)
                        .await?;
                }
                SessionChildToParent::FinalChildPid(raw_pid) => {
                    if let Some((backend, worker)) = &self.managed {
                        backend.final_metadata(worker);
                    }
                    break Pid::from_raw(raw_pid as i32);
                }
                SessionChildToParent::PamMessage { .. } => {
                    // pam_conv after start, ignore
                    ParentToSessionChild::PamResponse { resp: None }
                        .send(&mut self.sock)
                        .await?;
                    continue;
                }
                msg => panic!(
                    "expected Error or FinalChildPid from session worker, got: {:?}",
                    msg
                ),
            };
        };

        self.sock.shutdown(std::net::Shutdown::Both)?;

        self.started = true;
        Ok(SessionChild {
            task: self.task,
            sub_task,
            managed: self.managed.take(),
        })
    }
}
