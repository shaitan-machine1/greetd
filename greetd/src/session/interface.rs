use std::{
    ffi::CString,
    os::unix::{io::AsRawFd, net::UnixDatagram},
};

use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag},
    sys::signal::Signal,
    unistd::{execv, fork, ForkResult, Pid},
};

use async_trait::async_trait;

use tokio::net::UnixDatagram as TokioUnixDatagram;

use super::worker::{
    AuthMessageType, ParentToSessionChild, SessionChildToParent, SessionClass, TerminalMode,
};
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
impl AsyncSend for ParentToSessionChild<'_> {
    async fn send(&self, sock: &mut TokioUnixDatagram) -> Result<(), Error> {
        let mut out =
            serde_json::to_vec(self).map_err(|e| format!("unable to serialize message: {e}"))?;
        sock.send(&out)
            .await
            .map_err(|e| format!("unable to send message: {e}"))?;
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
            .map_err(|e| format!("unable to recieve message: {e}"))?;
        let msg = serde_json::from_slice(&data[..len])
            .map_err(|e| format!("unable to deserialize message: {e}"))?;
        Ok(msg)
    }
}

/// Tracks the processes spawned by a session
pub struct SessionChild {
    pub task: Pid,
    pub sub_task: Pid,
    teardown: Option<UnixDatagram>,
}

impl SessionChild {
    /// Check if this session has this pid.
    pub fn owns_pid(&self, pid: Pid) -> bool {
        self.task == pid
    }

    /// Send SIGTERM to the session child.
    pub fn term(&self) {
        let _ = nix::sys::signal::kill(self.sub_task, Signal::SIGTERM);
    }

    /// Send SIGKILL to the session child.
    pub fn kill(&self) {
        let _ = nix::sys::signal::kill(self.sub_task, Signal::SIGKILL);
        // In multiseatd mode the PAM host must survive to withdraw access.
        if self.teardown.is_none() {
            let _ = nix::sys::signal::kill(self.task, Signal::SIGKILL);
        }
    }

    /// Called after waitpid reports this PAM host's exit. Datagram sends precede
    /// exit, so no waiting, EOF assumption or controller-side seat RPC is needed.
    pub fn check_teardown(&mut self) {
        if let Some(sock) = self.teardown.take() {
            let mut data = [0; 10240];
            let result = sock
                .recv(&mut data)
                .map_err(Error::from)
                .and_then(|len| serde_json::from_slice(&data[..len]).map_err(Error::from));
            match result {
                Ok(SessionChildToParent::DeviceTeardown(result)) => require_teardown(result),
                _ => require_teardown(Err("PAM host exited without device-removal proof".into())),
            }
        }
    }
}

/// Stop this controller rather than letting a failed/uncertain withdrawal become
/// an ordinary authentication error followed by a successor Start. Existing
/// worker/compositor parent-death handling remains upstream's responsibility.
fn require_teardown(result: Result<(), Error>) {
    if let Err(error) = result {
        eprintln!("fatal: multiseatd device teardown is not complete: {error}");
        std::process::exit(1);
    }
}

#[derive(Debug)]
pub enum SessionState {
    Question(AuthMessageType, String),
    Ready,
}

/// A device to initiate a logged in PAM session.
pub struct Session {
    task: Pid,
    sock: TokioUnixDatagram,
    last_msg: Option<SessionChildToParent>,
    multiseatd: bool,
    removed: bool,
}

impl Session {
    /// Create a session started as an external process.
    pub fn new_external() -> Result<Session, Error> {
        // Pipe used to communicate the true PID of the final child.
        let (parentfd, childfd) =
            UnixDatagram::pair().map_err(|e| format!("could not create pipe: {e}"))?;

        // Tokio requires a nonblocking descriptor; cancellation deadlines must
        // remain pollable while a PAM host or SDK call is still running.
        parentfd.set_nonblocking(true)?;
        let raw_child = childfd.as_raw_fd();
        let mut cur_flags = FdFlag::from_bits_retain(fcntl(raw_child, FcntlArg::F_GETFD)?);
        cur_flags.remove(FdFlag::FD_CLOEXEC);
        fcntl(raw_child, FcntlArg::F_SETFD(cur_flags))?;

        // On Linux, /proc/self/exe is a reference to the original file, which remains valid
        // in spite of unlink or rename similar to an already open fd. It is, however, not very
        // portable. On FreeBSD, we would likely need to open our own process file early and rely
        // on fexecve, using the KERN_PROC_PATHNAME sysctl to get the path.
        #[allow(unreachable_code)]
        let child = match unsafe { fork() }.map_err(|e| format!("unable to fork: {e}"))? {
            ForkResult::Parent { child, .. } => child,
            ForkResult::Child => {
                execv(
                    &CString::new("/proc/self/exe").unwrap(),
                    &[
                        &CString::new("greetd").unwrap(),
                        &CString::new("--session-worker").unwrap(),
                        &CString::new(format!("{}", raw_child as usize)).unwrap(),
                    ],
                )
                .expect("unable to exec");

                unreachable!("after exec");
            }
        };

        Ok(Session {
            task: child,
            sock: TokioUnixDatagram::from_std(parentfd)?,
            last_msg: None,
            multiseatd: false,
            removed: false,
        })
    }

    /// Initiates the session, which will cause authentication to begin.
    #[allow(clippy::too_many_arguments)]
    pub async fn initiate(
        &mut self,
        service: &str,
        class: SessionClass,
        user: &str,
        authenticate: bool,
        term_mode: &TerminalMode,
        source_profile: bool,
        listener_path: &str,
    ) -> Result<(), Error> {
        self.multiseatd = matches!(term_mode, TerminalMode::Multiseatd { .. });
        let msg = ParentToSessionChild::InitiateLogin {
            service,
            class,
            user,
            authenticate,
            tty: term_mode.clone(),
            source_profile,
            listener_path,
        };
        msg.send(&mut self.sock).await?;
        Ok(())
    }

    async fn recv_message(&mut self) -> Result<SessionChildToParent, Error> {
        loop {
            let message = SessionChildToParent::recv(&mut self.sock).await;
            if self.multiseatd && !self.removed {
                if let Err(error) = &message {
                    require_teardown(Err(error.clone()));
                }
            }
            match message? {
                SessionChildToParent::DeviceTeardown(result) if self.multiseatd => {
                    require_teardown(result);
                    self.removed = true;
                }
                SessionChildToParent::Error(error) if self.multiseatd && !self.removed => {
                    require_teardown(Err("PAM host failed without device-removal proof".into()));
                    return Err(error);
                }
                message => return Ok(message),
            }
        }
    }

    /// Return the current state of this session.
    pub async fn get_state(&mut self) -> Result<SessionState, Error> {
        let msg = match self.last_msg.take() {
            Some(msg) => msg,
            None => self.recv_message().await?,
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
        let sent = ParentToSessionChild::Cancel.send(&mut self.sock).await;
        if self.multiseatd && !self.removed {
            require_teardown(sent.clone());
        }
        sent?;
        if self.multiseatd && !self.removed {
            let result = tokio::time::timeout(std::time::Duration::from_secs(12), async {
                while !self.removed {
                    match SessionChildToParent::recv(&mut self.sock).await? {
                        SessionChildToParent::DeviceTeardown(result) => {
                            require_teardown(result);
                            self.removed = true;
                        }
                        SessionChildToParent::PamMessage { .. } => {
                            ParentToSessionChild::PamResponse { resp: None }
                                .send(&mut self.sock)
                                .await?;
                        }
                        SessionChildToParent::Error(_) => {
                            return Err("PAM host failed without device-removal proof".into())
                        }
                        _ => {}
                    }
                }
                Ok::<(), Error>(())
            })
            .await;
            require_teardown(
                result.unwrap_or_else(|_| Err("device-removal result timed out".into())),
            );
        }
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

        let msg = self.recv_message().await?;

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
            match self.recv_message().await? {
                SessionChildToParent::Error(e) => return Err(e),
                SessionChildToParent::FinalChildPid(raw_pid) => {
                    break Pid::from_raw(raw_pid as i32)
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

        let teardown = if self.multiseatd {
            use std::os::fd::AsFd;
            let fd = self.sock.as_fd().try_clone_to_owned()?;
            Some(UnixDatagram::from(fd))
        } else {
            self.sock.shutdown(std::net::Shutdown::Both)?;
            None
        };

        Ok(SessionChild {
            task: self.task,
            sub_task,
            teardown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teardown_result_child() {
        let case = match std::env::var("GREETD_TEST_TEARDOWN_CASE") {
            Ok(case) => case,
            Err(_) => return,
        };
        let (parent, peer) = UnixDatagram::pair().unwrap();
        parent.set_nonblocking(true).unwrap();
        match case.as_str() {
            "success" | "later-pam-failure" => {
                SessionChildToParent::DeviceTeardown(Ok(()))
                    .send(&peer)
                    .unwrap();
                if case == "later-pam-failure" {
                    SessionChildToParent::Error("PAM close failed".into())
                        .send(&peer)
                        .unwrap();
                }
            }
            "pending" => {
                SessionChildToParent::DeviceTeardown(Err("Pending".into()))
                    .send(&peer)
                    .unwrap();
            }
            "error-without-proof" => {
                SessionChildToParent::Error("worker failed".into())
                    .send(&peer)
                    .unwrap();
            }
            "timeout" | "worker-death" => {}
            _ => panic!("unknown test case"),
        }
        drop(peer);
        let mut child = SessionChild {
            task: Pid::from_raw(1),
            sub_task: Pid::from_raw(1),
            teardown: Some(parent),
        };
        child.check_teardown();
        assert!(matches!(case.as_str(), "success" | "later-pam-failure"));
    }

    #[test]
    fn only_positive_device_result_authorizes_handoff() {
        for (case, code) in [
            ("success", 0),
            ("later-pam-failure", 0),
            ("pending", 1),
            ("timeout", 1),
            ("worker-death", 1),
            ("error-without-proof", 1),
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "session::interface::tests::teardown_result_child",
                    "--nocapture",
                ])
                .env("GREETD_TEST_TEARDOWN_CASE", case)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(code),
                "{}: {}",
                case,
                String::from_utf8_lossy(&output.stderr)
            );
            if code == 1 {
                assert!(String::from_utf8_lossy(&output.stderr)
                    .contains("device teardown is not complete"));
            }
        }
    }
}
