#![cfg(target_os = "linux")]

use std::{
    error::Error,
    ffi::{CStr, CString},
    fmt::Display
};

type InputCallback = dyn FnMut(bool, &str) -> String + Send;
type MsgCallback = dyn FnMut(bool, &str) + Send;

pub struct SimplePamAuthClient {
    service_name: CString,
    username: Option<CString>,

    input_callback: Option<Box<InputCallback>>,
    msg_callback: Option<Box<MsgCallback>>,
}

pub struct SimplePamAuthClientBuilder<'a> {
    service_name: &'a str,
    username: Option<&'a str>,

    input_callback: Option<Box<InputCallback>>,
    msg_callback: Option<Box<MsgCallback>>,
}

impl<'a> SimplePamAuthClientBuilder<'a> {
    pub fn new(service_name: &'a str) -> Self {
        Self {
            service_name,
            username: None,
            input_callback: None,
            msg_callback: None,
        }
    }

    pub fn username(mut self, username: &'a str) -> Self {
        self.username = Some(username);
        self
    }

    pub fn user_input_callback(
        mut self,
        callback: impl FnMut(bool, &str) -> String + Send + 'static,
    ) -> Self {
        self.input_callback = Some(Box::new(callback));
        self
    }

    pub fn msg_callback(mut self, callback: impl for <'b> FnMut(bool, &'b str) + Send + 'static) -> Self {
        self.msg_callback = Some(Box::new(callback));
        self
    }

    pub fn build(self) -> Result<SimplePamAuthClient, std::ffi::NulError> {
        let username = self.username.map(CString::new).transpose()?;
        Ok(SimplePamAuthClient {
            service_name: CString::new(self.service_name)?,
            username,
            input_callback: self.input_callback,
            msg_callback: self.msg_callback,
        })
    }
}

impl SimplePamAuthClient {
    pub fn authenticate(&mut self) -> Result<(), PamError> {
        let conv = pam_sys::pam_conv {
            appdata_ptr: self as *mut _ as *mut std::ffi::c_void,
            conv: Some(converse),
        };

        let mut pamh: PamHandle = PamHandle {
            handle: std::ptr::null_mut(),
            last_error: 0,
        };

        // SAFETY: service_name and username are valid CString pointers (or null_ptr for
        // username if None). conv is a valid pam_conv struct that lives for the duration
        // of the PAM session. pamh.handle is written to by pam_start on success.
        let res = unsafe {
            pam_sys::pam_start(
                self.service_name.as_ptr(),
                self.username
                    .as_ref()
                    .map(|u| u.as_ptr())
                    .unwrap_or_default(),
                &conv,
                &mut pamh.handle,
            )
        };
        if res != pam_sys::PAM_SUCCESS {
            pamh.last_error = res;
            return Err(PamError::from_code(res));
        }

        assert!(!pamh.handle.is_null());

        // SAFETY: pamh.handle is a valid PAM handle returned by a successful pam_start call
        // (verified non-null by the assert above).
        let res = unsafe { pam_sys::pam_authenticate(pamh.handle, 0) };
        if res != pam_sys::PAM_SUCCESS {
            pamh.last_error = res;
            return Err(PamError::from_code(res));
        }

        Ok(())
    }
}

struct PamHandle {
    handle: *mut pam_sys::pam_handle_t,
    last_error: std::ffi::c_int,
}
impl Drop for PamHandle {
    fn drop(&mut self) {
        if self.handle.is_null() {
            return;
        }

        // SAFETY: self.handle is a valid PAM handle from a successful pam_start call
        // (null handles are excluded by the early return above).
        unsafe {
            pam_sys::pam_end(self.handle, self.last_error);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PamError {
    AuthErr,
    Abort,
    CredInsufficient,
    AuthInfoUnavailable,
    MaxTries,
    UserUnknown,
    BufError,
    SystemError,
    Other(i32),
}
impl Error for PamError {}
impl Display for PamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PamError::AuthErr => write!(f, "Authentication error"),
            PamError::Abort => write!(f, "Authentication aborted"),
            PamError::CredInsufficient => write!(f, "Insufficient credentials"),
            PamError::AuthInfoUnavailable => write!(f, "Authentication info unavailable"),
            PamError::MaxTries => write!(f, "Maximum number of tries exceeded"),
            PamError::UserUnknown => write!(f, "User unknown"),
            PamError::BufError => write!(f, "Buffer error"),
            PamError::SystemError => write!(f, "System error"),
            PamError::Other(code) => write!(f, "Other PAM error: {}", code),
        }
    }
}

impl PamError {
    fn from_code(code: i32) -> Self {
        match code {
            pam_sys::PAM_AUTH_ERR => PamError::AuthErr,
            pam_sys::PAM_ABORT => PamError::Abort,
            pam_sys::PAM_CRED_INSUFFICIENT => PamError::CredInsufficient,
            pam_sys::PAM_AUTHINFO_UNAVAIL => PamError::AuthInfoUnavailable,
            pam_sys::PAM_MAXTRIES => PamError::MaxTries,
            pam_sys::PAM_USER_UNKNOWN => PamError::UserUnknown,
            pam_sys::PAM_BUF_ERR => PamError::BufError,
            pam_sys::PAM_SYSTEM_ERR => PamError::SystemError,
            other => PamError::Other(other),
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn converse(
    num_msg: i32,
    msg: *mut *const pam_sys::pam_message,
    resp: *mut *mut pam_sys::pam_response,
    appdata_ptr: *mut std::ffi::c_void,
) -> i32 {
    // SAFETY: appdata_ptr is guaranteed by PAM to be the same pointer passed in pam_conv.appdata_ptr,
    // which we set to point to our SimplePamAuthClient instance
    let auth_client = unsafe { &mut *(appdata_ptr as *mut SimplePamAuthClient) };

    if num_msg <= 0 || msg.is_null() || resp.is_null() {
        return pam_sys::PAM_BUF_ERR;
    }

    // SAFETY: msg is a valid pointer to an array of num_msg pointers to pam_message,
    // as guaranteed by the PAM conversation protocol.
    let msgs = unsafe { std::slice::from_raw_parts(msg, num_msg as usize) };

    // Allocate the response array using calloc, as required by PAM. The PAM module
    // will free this (and the individual resp strings) with free(3).
    // SAFETY: calloc is safe to call with any valid size arguments and returns null on failure.
    let resp_alloc = unsafe {
        libc::calloc(num_msg as usize, std::mem::size_of::<pam_sys::pam_response>())
    } as *mut pam_sys::pam_response;
    if resp_alloc.is_null() {
        return pam_sys::PAM_BUF_ERR;
    }
    // SAFETY: resp is a valid non-null pointer (checked above at line 177).
    // We store our calloc'd array as required by the PAM conversation protocol.
    unsafe { *resp = resp_alloc };
    // SAFETY: resp_alloc was just successfully allocated by calloc for num_msg elements,
    // so it is valid, properly aligned, and initialized (zeroed).
    let responses = unsafe { std::slice::from_raw_parts_mut(resp_alloc, num_msg as usize) };

    for (msg_ptr, resp) in msgs.iter().zip(responses.iter_mut()) {
        // SAFETY: Each element in the msg array is a valid pointer to a pam_message,
        // as guaranteed by PAM.
        let msg = unsafe { &**msg_ptr };
        let msg_str = if msg.msg.is_null() {
            ""
        } else {
            // SAFETY: msg.msg is guaranteed by PAM to be a valid null-terminated C string
            let cstr = unsafe { CStr::from_ptr(msg.msg) };
            match cstr.to_str() {
                Ok(s) => s,
                _ => {
                    return pam_sys::PAM_CONV_ERR;
                }
            }
        };

        match msg.msg_style {
            pam_sys::PAM_PROMPT_ECHO_OFF | pam_sys::PAM_PROMPT_ECHO_ON => {
                if let Some(input_callback) = &mut auth_client.input_callback {
                    let echo_on = msg.msg_style == pam_sys::PAM_PROMPT_ECHO_ON;
                    let response_str = input_callback(echo_on, msg_str);
                    let c_response = match CString::new(response_str) {
                        Ok(cstr) => cstr,
                        Err(_) => return pam_sys::PAM_CONV_ERR,
                    };
                    // SAFETY: c_response is guaranteed to be a valid null-terminated C string,
                    // and pam_response.resp is expected by PAM to be freed by PAM using free()
                    resp.resp = unsafe { libc::strdup(c_response.as_ptr()) };
                    resp.resp_retcode = 0; // Unused field, man page tells to set to 0
                } else {
                    return pam_sys::PAM_CONV_ERR;
                }
            }
            pam_sys::PAM_ERROR_MSG | pam_sys::PAM_TEXT_INFO => {
                if let Some(msg_callback) = &mut auth_client.msg_callback {
                    msg_callback(
                        msg.msg_style == pam_sys::PAM_ERROR_MSG,
                        msg_str,
                    );
                } else {
                    return pam_sys::PAM_CONV_ERR;
                }
            }
            _ => {
                // Unsupported message style
                return pam_sys::PAM_CONV_ERR;
            }
        }
    }

    pam_sys::PAM_SUCCESS
}
