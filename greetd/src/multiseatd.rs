//! The PAM worker owns a context; the controller never owns seat authority.
use std::os::fd::{AsFd, AsRawFd, RawFd};

use libmultiseatd::{Client, Context};
use serde::{Deserialize, Serialize};

use crate::{error::Error, pam::session::PamSession};
use pam_sys::PamItemType;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub seat: String,
    /// Zero is the API representation of the explicit configuration value "none".
    pub vt: u32,
}

impl Config {
    pub fn metadata(&self, pam: &mut PamSession<'_>) -> Result<(), Error> {
        pam.putenv(&format!("XDG_SEAT={}", self.seat))?;
        if self.vt == 0 {
            pam.unsetenv("XDG_VTNR")?;
        } else {
            pam.set_item(PamItemType::TTY, &format!("tty{}", self.vt))?;
            pam.putenv(&format!("XDG_VTNR={}", self.vt))?;
        }
        Ok(())
    }
}

pub struct SeatContext {
    client: Client,
    context: Context,
}

impl SeatContext {
    pub fn create(config: &Config) -> Result<Self, Error> {
        let client =
            Client::system(&config.seat).map_err(|e| format!("multiseatd connect: {e}"))?;
        let context = client
            .create_context(config.vt)
            .map_err(|e| format!("multiseatd CreateContext: {e}"))?;
        Ok(Self { client, context })
    }

    pub fn activate(&self, uid: u32, foreground: bool) -> Result<(), Error> {
        self.client
            .add_acl_grant(self.context.as_fd(), uid)
            .map_err(|e| format!("multiseatd AddAclGrant: {e}"))?;
        self.client
            .activate_context(self.context.id)
            .map_err(|e| format!("multiseatd ActivateContext: {e}"))?;
        if foreground {
            self.client
                .move_to_foreground(self.context.id)
                .map_err(|e| format!("multiseatd MoveToForeground: {e}"))?;
        }
        Ok(())
    }

    pub fn authority(&self) -> RawFd {
        self.context.as_fd().as_raw_fd()
    }

    pub fn remove(self) -> Result<(), Error> {
        self.client
            .remove_context(self.context.as_fd())
            .map_err(|e| format!("multiseatd RemoveContext: {e}").into())
    }
}

/// Run only in the fresh exec'd PAM worker, before opening bus/PAM descriptors.
pub fn prepare_worker() -> Result<(), Error> {
    libmultiseatd::launch::fill_standard_streams()?;
    nix::unistd::setsid()?;
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::getppid() } == 1 {
        return Err("controller exited before PAM worker setup".into());
    }
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    for fd in 0..=2 {
        // Retain supervisor log pipes and safe PTYs, never a Linux console.
        let replace = fd == 0
            || libmultiseatd::launch::is_linux_vt(unsafe {
                std::os::fd::BorrowedFd::borrow_raw(fd)
            })?;
        if replace && unsafe { libc::dup2(null.as_raw_fd(), fd) } == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

/// Called only in the final fork child. No RPC, PAM, allocation or FD enumeration.
/// Linux close_range(CLOEXEC) keeps PAM-owned descriptors intact until exec while
/// preventing all but the deliberately delegated authority from surviving it.
pub fn inherit_authority(authority: RawFd) -> Result<(), nix::errno::Errno> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    nix::errno::Errno::result(result)?;
    nix::errno::Errno::result(unsafe { libc::fcntl(authority, libc::F_SETFD, 0) })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fd_hygiene_child() {
        if std::env::var_os("GREETD_TEST_FD_CHILD").is_none() {
            return;
        }
        let (authority, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let unrelated = std::fs::File::open("/dev/null").unwrap();
        unsafe {
            libc::fcntl(unrelated.as_raw_fd(), libc::F_SETFD, 0);
        }
        inherit_authority(authority.as_raw_fd()).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(authority.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        for fd in [peer.as_raw_fd(), unrelated.as_raw_fd()] {
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
    }

    #[test]
    fn only_explicit_authority_can_survive_exec() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "multiseatd::tests::fd_hygiene_child"])
            .env("GREETD_TEST_FD_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
