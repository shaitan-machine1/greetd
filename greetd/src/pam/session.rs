use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    pin::Pin,
    ptr,
};

use libc::c_void;
use pam_sys::{PamFlag, PamHandle, PamItemType, PamReturnCode};

use super::{
    converse::Converse,
    env::{get_pam_env, PamEnvList},
    ffi::{make_conversation, PamConvHandlerWrapper},
    PamError,
};

pub struct PamSession<'a> {
    handle: *mut PamHandle,
    opened: bool,
    credentials: bool,
    ended: bool,
    #[allow(unused)]
    lifetime_extender: Pin<Box<PamConvHandlerWrapper<'a>>>,
    last_code: PamReturnCode,
}

impl<'a> PamSession<'a> {
    pub fn start(
        service: &str,
        user: &str,
        pam_conv: Pin<Box<dyn Converse + 'a>>,
        directory: Option<&str>,
    ) -> Result<PamSession<'a>, PamError> {
        let mut pch = Box::pin(PamConvHandlerWrapper { handler: pam_conv });
        let conv = make_conversation(&mut pch);
        let mut pam_handle: *mut PamHandle = ptr::null_mut();

        let result = if let Some(directory) = directory {
            private_start(service, user, &conv, directory, &mut pam_handle)?
        } else {
            pam_sys::start(service, Some(user), &conv, &mut pam_handle)
        };
        match result {
            PamReturnCode::SUCCESS => Ok(PamSession {
                handle: pam_handle,
                opened: false,
                credentials: false,
                ended: false,
                lifetime_extender: pch,
                last_code: PamReturnCode::SUCCESS,
            }),
            rc => Err(PamError::from_rc("pam_start", rc)),
        }
    }

    pub fn authenticate(&mut self, flags: PamFlag) -> Result<(), PamError> {
        self.last_code = pam_sys::authenticate(self.live_handle(), flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_authenticate", rc)),
        }
    }

    pub fn acct_mgmt(&mut self, flags: PamFlag) -> Result<(), PamError> {
        self.last_code = pam_sys::acct_mgmt(self.live_handle(), flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_acct_mgmt", rc)),
        }
    }

    pub fn setcred(&mut self, flags: PamFlag) -> Result<(), PamError> {
        // Earlier credential modules may succeed before a later module fails.
        if flags == PamFlag::ESTABLISH_CRED {
            self.credentials = true;
        }
        if flags == PamFlag::DELETE_CRED {
            self.credentials = false;
        }
        self.last_code = pam_sys::setcred(self.live_handle(), flags);
        if self.last_code == PamReturnCode::SUCCESS {
            if flags == PamFlag::ESTABLISH_CRED {
                self.credentials = true;
            }
            if flags == PamFlag::DELETE_CRED {
                self.credentials = false;
            }
        }
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_setcred", rc)),
        }
    }

    pub fn open_session(&mut self, flags: PamFlag) -> Result<(), PamError> {
        // A later required module can fail after earlier session participants
        // opened successfully. Pair the attempt with one close during unwind.
        self.opened = true;
        self.last_code = pam_sys::open_session(self.live_handle(), flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_open_session", rc)),
        }
    }

    pub fn close_session(&mut self, flags: PamFlag) -> Result<(), PamError> {
        self.opened = false;
        self.last_code = pam_sys::close_session(self.live_handle(), flags);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_close_session", rc)),
        }
    }

    pub fn putenv(&mut self, v: &str) -> Result<(), PamError> {
        self.last_code = pam_sys::putenv(self.live_handle(), v);
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_putenv", rc)),
        }
    }

    pub fn set_item(&mut self, item: PamItemType, value: &str) -> Result<(), PamError> {
        let s = CString::new(value).unwrap();
        self.last_code = PamReturnCode::from(unsafe {
            // pam_set_item is exposed in a weird way in pam_sys::wrapped, so
            // we use the raw version here instead
            pam_sys::raw::pam_set_item(self.handle, item as i32, s.as_ptr() as *const c_void)
        });
        match self.last_code {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_set_item", rc)),
        }
    }

    pub fn get_user(&mut self) -> Result<String, PamError> {
        let mut p: *const c_char = ptr::null_mut();
        self.last_code = pam_sys::get_user(self.live_handle(), &mut p, ptr::null());
        match self.last_code {
            PamReturnCode::SUCCESS => {
                Ok((unsafe { CStr::from_ptr(p) }).to_str().unwrap().to_string())
            }
            rc => Err(PamError::from_rc("pam_get_user", rc)),
        }
    }

    pub fn getenvlist(&mut self) -> Result<PamEnvList, PamError> {
        match get_pam_env(self.live_handle()) {
            Some(v) => Ok(v),
            None => Err(PamError::Error(
                "unable to retrieve environment".to_string(),
            )),
        }
    }

    fn live_handle(&mut self) -> &mut PamHandle {
        assert!(!self.ended);
        unsafe { &mut *self.handle }
    }

    pub fn end(&mut self) -> Result<(), PamError> {
        if self.ended {
            return Ok(());
        }
        self.ended = true;
        match PamReturnCode::from(unsafe {
            pam_sys::raw::pam_end(self.handle, self.last_code as i32)
        }) {
            PamReturnCode::SUCCESS => Ok(()),
            rc => Err(PamError::from_rc("pam_end", rc)),
        }
    }
}

impl Drop for PamSession<'_> {
    fn drop(&mut self) {
        if self.ended {
            return;
        }
        if self.opened {
            if let Err(error) = self.close_session(PamFlag::NONE) {
                eprintln!("PAM close cleanup: {}", error);
            }
        }
        if self.credentials {
            if let Err(error) = self.setcred(PamFlag::DELETE_CRED) {
                eprintln!("PAM credential cleanup: {}", error);
            }
        }
        if let Err(error) = self.end() {
            eprintln!("PAM end cleanup: {}", error);
        }
    }
}

#[cfg(feature = "test-support")]
fn private_start(
    service: &str,
    user: &str,
    conversation: &pam_sys::PamConversation,
    directory: &str,
    handle: &mut *mut PamHandle,
) -> Result<PamReturnCode, PamError> {
    unsafe extern "C" {
        fn pam_start_confdir(
            service: *const c_char,
            user: *const c_char,
            conversation: *const pam_sys::PamConversation,
            directory: *const c_char,
            handle: *mut *mut PamHandle,
        ) -> i32;
    }
    let value = |text: &str| CString::new(text).map_err(|error| PamError::Error(error.to_string()));
    let service = value(service)?;
    let user = value(user)?;
    let directory = value(directory)?;
    Ok(PamReturnCode::from(unsafe {
        pam_start_confdir(
            service.as_ptr(),
            user.as_ptr(),
            conversation,
            directory.as_ptr(),
            handle,
        )
    }))
}
#[cfg(not(feature = "test-support"))]
fn private_start(
    _: &str,
    _: &str,
    _: &pam_sys::PamConversation,
    _: &str,
    _: &mut *mut PamHandle,
) -> Result<PamReturnCode, PamError> {
    Err(PamError::Error(
        "private PAM fixtures require test-support".into(),
    ))
}
