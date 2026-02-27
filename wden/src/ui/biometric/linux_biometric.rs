use std::{
    ffi::CString,
    sync::{ Arc, atomic::{AtomicBool, Ordering}, },
};

use anyhow::Context;
use cursive::{Cursive, view::Nameable, views::Dialog};
use pam::Conversation;

use crate::ui::util::cursive_ext::{CursiveCallbackExt, CursiveExt};

pub struct CursiveConversation {
    cb_sink: cursive::CbSink,
    username: CString,
    cancelled: Arc<AtomicBool>,
}

impl CursiveConversation {
    pub fn new(cb_sink: cursive::CbSink, username: CString) -> Self {
        Self {
            cb_sink,
            username,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub fn start_verify_biometric_auth<F: FnOnce(&mut Cursive, bool) + Send + 'static>(
    cursive: &mut Cursive,
    callback: F,
) -> anyhow::Result<()> {
    let mut client = pam::Client::with_conversation(
        "wden",
        CursiveConversation::new(cursive.cb_sink().clone(), get_username()?),
    )
    .context("Client creation fail")?;

    client.close_on_drop = true;

    cursive.async_op(async move { client.authenticate() }, |siv, res| {
        pop_pam_msg_dialog(siv);
        match res {
            Ok(()) => callback(siv, true),
            Err(e) => {
                log::error!("Biometric err: {:?}", e);
                callback(siv, false);
            }
        }
    });

    Ok(())
}

pub fn is_biometric_unlock_supported() -> bool {
    // Assume a standard pam config. Check if the pam config file
    // for wden is defined. There's not really a better way to check this without
    // trying an auth cycle.
    const PAM_CONFIG_FILE: &str = "/etc/pam.d/wden";
    let Ok(metadata) = std::fs::metadata(PAM_CONFIG_FILE) else {
        return false;
    };
    metadata.is_file()
}

impl Conversation for CursiveConversation {
    fn prompt_echo(&mut self, msg: &std::ffi::CStr) -> Result<std::ffi::CString, ()> {
        self.check_cancelled()?;
        // respond to "login: " with the current username
        if msg.to_bytes().starts_with(b"login:") {
            Ok(self.username.clone())
        } else {
            Ok(CString::default())
        }
    }

    fn prompt_blind(&mut self, _msg: &std::ffi::CStr) -> Result<std::ffi::CString, ()> {
        self.check_cancelled()?;
        Ok(CString::default())
    }

    fn info(&mut self, msg: &std::ffi::CStr) {
        if self.check_cancelled().is_err() {
            return;
        };
        self.replace_pam_msg_dialog(msg);
    }

    fn error(&mut self, msg: &std::ffi::CStr) {
        if self.check_cancelled().is_err() {
            return;
        };
        self.replace_pam_msg_dialog(msg);
    }
}

impl CursiveConversation {
    fn replace_pam_msg_dialog(&mut self, msg: &std::ffi::CStr) {
        let msg = msg.to_string_lossy().to_string();
        let cancel_flag = Arc::clone(&self.cancelled);
        self.cb_sink.send_msg(Box::new(move |siv| {
            pop_pam_msg_dialog(siv);
            let dialog = Dialog::text(msg).button("Cancel", move |siv| {
                siv.pop_layer();
                cancel_flag.store(true, Ordering::Relaxed);
            });
            siv.add_layer(dialog.with_name("pam_dialog"));
        }));
    }

    fn check_cancelled(&self) -> Result<(), ()> {
        if self.cancelled.load(Ordering::Relaxed) {
            Err(())
        } else {
            Ok(())
        }
    }
}

fn get_username() -> anyhow::Result<CString> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())?;
    let user = user.context("User info not found with current uid")?;
    Ok(CString::new(user.name)?)
}

fn pop_pam_msg_dialog(siv: &mut Cursive) {
    if siv.find_name::<Dialog>("pam_dialog").is_some() {
        siv.pop_layer();
    }
}
