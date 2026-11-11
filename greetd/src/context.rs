use std::{
    fs::File,
    path::Path,
    time::{Duration, Instant},
};

use nix::{
    sys::wait::{waitpid, WaitPidFlag, WaitStatus},
    unistd::alarm,
};
use tokio::{sync::RwLock, time::sleep};

use crate::{
    error::Error,
    scrambler::Scrambler,
    session::{
        interface::{Session, SessionChild, SessionState},
        worker::{
            AuthMessageType as SessAuthMessageType, ParentToSessionChild, SessionClass,
            TerminalMode,
        },
    },
};
use greetd_ipc::AuthMessageType;

struct SessionChildSet {
    child: SessionChild,
    time: Instant,
    is_greeter: bool,
}

struct SessionSet {
    session: Session,
    time: Instant,
}

struct ContextInner {
    current: Option<SessionChildSet>,
    scheduled: Option<SessionSet>,
    configuring: Option<SessionSet>,
}

/// Context keeps track of running sessions and start new ones.
pub struct Context {
    inner: RwLock<ContextInner>,
    greeter_bin: String,
    greeter_user: String,
    greeter_service: String,
    pam_service: String,
    term_mode: TerminalMode,
    source_profile: bool,
    runfile: String,
    listener_path: String,
    backend: Option<crate::managed::Backend>,
    initial_greeter_started: std::cell::Cell<bool>,
}

impl Context {
    pub fn new(
        config: crate::config::ConfigFile,
        term_mode: TerminalMode,
        listener_path: String,
        backend: Option<crate::managed::Backend>,
    ) -> Context {
        Context {
            inner: RwLock::new(ContextInner {
                current: None,
                scheduled: None,
                configuring: None,
            }),
            greeter_bin: config.default_session.command,
            greeter_user: config.default_session.user,
            greeter_service: config.default_session.service,
            pam_service: config.general.service,
            term_mode,
            source_profile: config.general.source_profile,
            runfile: config.general.runfile,
            listener_path,
            backend,
            initial_greeter_started: std::cell::Cell::new(false),
        }
    }

    /// Directly start an unauthenticated session, bypassing the normal
    /// scheduling. This function does not take the inner lock, and can thus
    /// be used while it is held.
    async fn start_unauthenticated_session(
        &self,
        class: SessionClass,
        user: &str,
        service: &str,
        cmd: Vec<String>,
    ) -> Result<SessionChild, Error> {
        if let TerminalMode::Managed(settings) = &self.term_mode {
            settings.arguments(&cmd)?;
        }
        let foreground =
            matches!(class, SessionClass::Greeter) && !self.initial_greeter_started.replace(true);
        let mut scheduled_session = Session::new_external(self.backend.clone())?;
        scheduled_session
            .initiate(ParentToSessionChild::InitiateLogin {
                service,
                class,
                user,
                authenticate: false,
                foreground,
                tty: self.term_mode.clone(),
                source_profile: self.source_profile,
                listener_path: &self.listener_path,
            })
            .await?;
        loop {
            match scheduled_session.get_state().await {
                Ok(SessionState::Ready) => break,
                Ok(SessionState::Question(_, _)) => scheduled_session.post_response(None).await?,
                Err(err) => return Err(format!("session start failed: {}", err).into()),
            }
        }

        scheduled_session.send_args(cmd, vec![]).await?;
        tokio::time::timeout(Duration::from_secs(60), scheduled_session.start())
            .await
            .map_err(|_| Error::Error("session startup deadline exceeded".into()))?
    }

    /// Directly start a greeter session, bypassing the normal scheduling. This
    /// function does not take the inner lock, and can thus be used while it is
    /// held.
    async fn start_greeter(&self) -> Result<SessionChild, Error> {
        self.start_unauthenticated_session(
            SessionClass::Greeter,
            &self.greeter_user,
            &self.greeter_service,
            vec![self.greeter_bin.to_string()],
        )
        .await
    }

    /// Directly start a greeter session, bypassing the normal scheduling.
    pub async fn greet(&self) -> Result<(), Error> {
        {
            let inner = self.inner.read().await;
            if inner.current.is_some() {
                return Err("session already active".into());
            }
        }

        let mut inner = self.inner.write().await;
        inner.current = Some(SessionChildSet {
            child: self.start_greeter().await?,
            time: Instant::now(),
            is_greeter: true,
        });
        Ok(())
    }

    /// Check if this is the first time greetd starts since boot, or if it restarted for any reason
    pub fn is_first_run(&self) -> bool {
        !Path::new(&self.runfile).exists()
    }

    /// Create runfile used to check if greetd was already started since boot
    pub fn create_runfile(&self) {
        if let Err(err) = File::create(&self.runfile) {
            eprintln!("could not create runfile: {}", err);
        }
    }

    /// Directly start an initial session, bypassing the normal scheduling.
    pub async fn start_user_session(&self, user: &str, cmd: Vec<String>) -> Result<(), Error> {
        {
            let inner = self.inner.read().await;
            if inner.current.is_some() {
                return Err("session already active".into());
            }
        }

        let mut inner = self.inner.write().await;
        inner.current = Some(SessionChildSet {
            child: self
                .start_unauthenticated_session(SessionClass::User, user, &self.pam_service, cmd)
                .await?,
            time: Instant::now(),
            is_greeter: false,
        });
        Ok(())
    }

    /// Create a new session for configuration.
    pub async fn create_session(&self, username: String) -> Result<(), Error> {
        {
            let inner = self.inner.read().await;
            if inner.current.is_none() {
                return Err("session not active".into());
            }
            if self.backend.is_some()
                && inner
                    .current
                    .as_ref()
                    .is_some_and(|session| !session.is_greeter)
            {
                return Err("only the current greeter may configure a login".into());
            }
            if inner.configuring.is_some() {
                return Err("a session is already being configured".into());
            }
            if inner.scheduled.is_some() {
                return Err("a session is already scheduled".into());
            }
        }

        let mut session_set = SessionSet {
            session: Session::new_external(self.backend.clone())?,
            time: Instant::now(),
        };
        session_set
            .session
            .initiate(ParentToSessionChild::InitiateLogin {
                service: &self.pam_service,
                class: SessionClass::User,
                user: &username,
                authenticate: true,
                foreground: false,
                tty: self.term_mode.clone(),
                source_profile: self.source_profile,
                listener_path: &self.listener_path,
            })
            .await?;

        let mut session = Some(session_set);
        let mut inner = self.inner.write().await;
        std::mem::swap(&mut session, &mut inner.configuring);
        drop(inner);

        // If there was a session under configuration, cancel it.
        if let Some(mut s) = session {
            s.session.cancel().await?;
        }

        Ok(())
    }

    /// Cancel the session being configured.
    pub async fn cancel(&self) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        if let Some(mut s) = inner.configuring.take() {
            s.session.cancel().await?;
        }
        Ok(())
    }

    /// Retrieve a question from the session under configuration.
    pub async fn get_question(&self) -> Result<Option<(AuthMessageType, String)>, Error> {
        let mut inner = self.inner.write().await;
        match &mut inner.configuring {
            Some(s) => match s.session.get_state().await? {
                SessionState::Ready => Ok(None),
                SessionState::Question(style, string) => Ok(Some((
                    match style {
                        SessAuthMessageType::Visible => AuthMessageType::Visible,
                        SessAuthMessageType::Secret => AuthMessageType::Secret,
                        SessAuthMessageType::Info => AuthMessageType::Info,
                        SessAuthMessageType::Error => AuthMessageType::Error,
                    },
                    string,
                ))),
            },
            None => Err("no session under configuration".into()),
        }
    }

    /// Answer a question to the session under configuration.
    pub async fn post_response(&self, answer: Option<String>) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        match &mut inner.configuring {
            Some(s) => match s.session.get_state().await? {
                SessionState::Ready => Err("session has no pending questions".into()),
                _ => s.session.post_response(answer).await,
            },
            None => {
                if let Some(mut answer) = answer {
                    answer.scramble();
                }
                Err("no session under configuration".into())
            }
        }
    }

    /// Schedule the session under configuration with the provided arguments.
    pub async fn start(&self, cmd: Vec<String>, env: Vec<String>) -> Result<(), Error> {
        if let TerminalMode::Managed(settings) = &self.term_mode {
            settings.arguments(&cmd)?;
        }
        let mut session = self.inner.write().await.configuring.take();

        match &mut session {
            Some(s) => match s.session.get_state().await? {
                SessionState::Ready => {
                    // Send our arguments to the session.
                    s.session.send_args(cmd, env).await?;

                    let mut inner = self.inner.write().await;
                    std::mem::swap(&mut session, &mut inner.scheduled);
                    drop(inner);

                    // If there was a scheduled session, cancel it.
                    if let Some(mut p) = session {
                        p.session.cancel().await?;
                    }

                    // We give the greeter 5 seconds to prove itself well-behaved before
                    // we lose patience and shoot it in the back repeatedly. This is all
                    // handled by our alarm handler.
                    alarm::set(5);

                    Ok(())
                }
                SessionState::Question(..) => Err("session is not ready".into()),
            },
            None => Err("no session active".into()),
        }
    }

    /// Only an explicit positive device result authorizes normal handoff.
    /// PAM close/final worker exit are independent, possibly much later events.
    pub async fn check_workers(&self) -> Result<(), Error> {
        if self.backend.is_none() {
            return Ok(());
        }
        let mut inner = self.inner.write().await;
        let ready = match &inner.current {
            Some(current) => current.child.device_result()?.is_some(),
            None => false,
        };
        if !ready {
            return Ok(());
        }
        let previous = inner.current.take().expect("completed current worker");
        let elapsed = previous.time.elapsed();
        drop(previous);
        if let Some(mut scheduled) = inner.scheduled.take() {
            drop(inner);
            let child = tokio::time::timeout(Duration::from_secs(60), scheduled.session.start())
                .await
                .map_err(|_| Error::Error("session startup deadline exceeded".into()))??;
            self.inner.write().await.current = Some(SessionChildSet {
                child,
                time: Instant::now(),
                is_greeter: false,
            });
        } else {
            if let Some(mut configuring) = inner.configuring.take() {
                configuring.session.cancel().await?;
            }
            if elapsed < Duration::from_secs(1) {
                sleep(Duration::from_secs(1)).await;
            }
            inner.current = Some(SessionChildSet {
                child: self.start_greeter().await?,
                time: Instant::now(),
                is_greeter: true,
            });
        }
        Ok(())
    }

    /// Notify the Context of an alarm.
    pub async fn alarm(&self) -> Result<(), Error> {
        if self.backend.is_some() {
            self.check_workers().await?;
            let inner = self.inner.read().await;
            if inner.scheduled.is_some() {
                if let Some(current) = &inner.current {
                    current.child.term();
                }
                alarm::set(1);
            }
            return Ok(());
        }
        // Keep trying to terminate the greeter until it gives up.
        let mut inner = self.inner.write().await;

        if let Some(mut p) = inner.scheduled.take() {
            if let Some(g) = inner.current.take() {
                if p.time.elapsed() > Duration::from_secs(10) {
                    // We're out of patience.
                    g.child.kill();
                } else {
                    // Let's try to give it a gentle nudge.
                    g.child.term();
                }
                inner.current = Some(g);
                inner.scheduled = Some(p);
                alarm::set(1);
                return Ok(());
            }
            drop(inner);
            let s = match tokio::time::timeout(Duration::from_secs(60), p.session.start())
                .await
                .map_err(|_| Error::Error("session startup deadline exceeded".into()))?
            {
                Ok(s) => s,
                Err(e) => return Err(format!("session start failed: {}", e).into()),
            };
            let mut inner = self.inner.write().await;
            inner.current = Some(SessionChildSet {
                child: s,
                time: Instant::now(),
                is_greeter: false,
            });
        }

        Ok(())
    }

    /// Notify the Context that it needs to check its children for termination.
    /// This should be called on SIGCHLD.
    pub async fn check_children(&self) -> Result<(), Error> {
        loop {
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                // No scheduled exits.
                Ok(WaitStatus::StillAlive) => break Ok(()),

                // We got an exit, see if it's something we need to clean up.
                Ok(WaitStatus::Exited(pid, ..)) | Ok(WaitStatus::Signaled(pid, ..)) => {
                    if self.backend.is_some() {
                        self.check_workers().await?;
                        continue;
                    }
                    let mut inner = self.inner.write().await;
                    let (was_greeter, sesion_length) = match &inner.current {
                        Some(s) if s.child.owns_pid(pid) => {
                            let res = (s.is_greeter, s.time.elapsed());
                            inner.current = None;
                            res
                        }
                        _ => continue,
                    };

                    match inner.scheduled.take() {
                        Some(mut scheduled) => {
                            // Our greeter finally bit the dust so we can
                            // start our scheduled session.
                            drop(inner);
                            let s = match tokio::time::timeout(
                                Duration::from_secs(60),
                                scheduled.session.start(),
                            )
                            .await
                            .map_err(|_| Error::Error("session startup deadline exceeded".into()))?
                            {
                                Ok(s) => s,
                                Err(e) => return Err(format!("session start failed: {}", e).into()),
                            };
                            let mut inner = self.inner.write().await;
                            inner.current = Some(SessionChildSet {
                                child: s,
                                time: Instant::now(),
                                is_greeter: false,
                            });
                        }
                        None => {
                            if was_greeter && self.backend.is_none() {
                                return Err("greeter exited without creating a session".into());
                            }
                            if sesion_length < Duration::from_secs(1) {
                                sleep(Duration::from_secs(1)).await;
                            }
                            inner.current = Some(SessionChildSet {
                                child: self.start_greeter().await?,
                                time: Instant::now(),
                                is_greeter: true,
                            });
                        }
                    }
                }

                // Useless status.
                Ok(_) => continue,

                // Interrupted.
                Err(nix::errno::Errno::EINTR) => continue,

                // We do not have any children right now.
                Err(nix::errno::Errno::ECHILD) => break Ok(()),

                // Uh, what?
                Err(e) => panic!("waitpid returned an unexpected error: {}", e),
            }
        }
    }

    /// Notify the Context that we want to terminate. This should be called on
    /// SIGTERM.
    pub async fn terminate(&self) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        if let Some(mut sess) = inner.configuring.take() {
            let _ = sess.session.cancel().await;
        }
        if let Some(mut sess) = inner.scheduled.take() {
            let _ = sess.session.cancel().await;
        }
        if let Some(sess) = inner.current.take() {
            sess.child.term();
            if self.backend.is_some() {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    match waitpid(sess.child.task, Some(WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::StillAlive) if Instant::now() < deadline => {
                            sleep(Duration::from_millis(25)).await
                        }
                        Ok(WaitStatus::StillAlive) => {
                            sess.child.kill();
                            break;
                        }
                        _ => break,
                    }
                }
            }
        }
        Ok(())
    }
}
