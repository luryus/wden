use cursive::Cursive;

pub fn start_verify_biometric_auth<F: FnOnce(&mut Cursive, bool) -> () + Send + 'static>(
    cursive: &mut Cursive,
    callback: F,
) -> anyhow::Result<()> {
    linux_biometric::start_verify_biometric_auth(cursive, callback)
}

mod linux_biometric {
    use std::ffi::CString;

    use anyhow::Context;
    use cursive::{Cursive, view::Nameable, views::Dialog};
    use pam::Conversation;

    use crate::ui::util::cursive_ext::{CursiveCallbackExt, CursiveExt};

    pub struct CursiveConversation {
        cb_sink: cursive::CbSink,
        username: CString,
    }

    impl CursiveConversation {
        pub fn new(cb_sink: cursive::CbSink, username: CString) -> Self {
            Self { cb_sink, username }
        }
    }

    pub fn start_verify_biometric_auth<F: FnOnce(&mut Cursive, bool) -> () + Send + 'static>(
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

    impl Conversation for CursiveConversation {
        fn prompt_echo(&mut self, msg: &std::ffi::CStr) -> Result<std::ffi::CString, ()> {
            // respond to "login: " with the current username
            if msg.to_bytes().starts_with(b"login:") {
                Ok(self.username.clone())
            } else {
                Ok(CString::default())
            }
        }

        fn prompt_blind(&mut self, msg: &std::ffi::CStr) -> Result<std::ffi::CString, ()> {
            Ok(CString::default())
        }

        fn info(&mut self, msg: &std::ffi::CStr) {
            self.replace_pam_msg_dialog(msg);
        }

        fn error(&mut self, msg: &std::ffi::CStr) {
            self.replace_pam_msg_dialog(msg);
        }
    }

    impl CursiveConversation {
        fn replace_pam_msg_dialog(&self, msg: &std::ffi::CStr) {
            let msg = msg.to_string_lossy().to_string();
            self.cb_sink.send_msg(Box::new(move |siv| {
                pop_pam_msg_dialog(siv);
                let dialog = Dialog::text(msg);
                siv.add_layer(dialog.with_name("pam_dialog"));
            }));
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
}
