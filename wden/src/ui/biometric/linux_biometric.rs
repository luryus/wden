use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::Context;
use cursive::{Cursive, view::Nameable, views::Dialog};
use simple_pam_auth::SimplePamAuthClientBuilder;

use crate::ui::util::cursive_ext::{CursiveCallbackExt, CursiveExt};

pub fn start_verify_biometric_auth<F: FnOnce(&mut Cursive, bool) + Send + 'static>(
    cursive: &mut Cursive,
    callback: F,
) -> anyhow::Result<()> {
    let username = get_username()?;

    let cancelled = Arc::new(AtomicBool::new(false));
    let cb_sink = cursive.cb_sink().clone();

    let cb = move |_is_error: bool, msg: &str| {
        let c = Arc::clone(&cancelled);
        if c.load(Ordering::Relaxed) {
            return;
        }
        replace_pam_msg_dialog(&cb_sink, c, msg);
    };

    let mut client = SimplePamAuthClientBuilder::new("wden")
        .username(&username)
        .msg_callback(cb)
        .build()?;

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

fn replace_pam_msg_dialog(
    cb_sink: &cursive::CbSink,
    cancel_flag: Arc<AtomicBool>,
    msg: impl Into<String>,
) {
    let msg = msg.into();
    cb_sink.send_msg(Box::new(move |siv| {
        pop_pam_msg_dialog(siv);
        let dialog = Dialog::text(msg).button("Cancel", move |siv| {
            siv.pop_layer();
            cancel_flag.store(true, Ordering::Relaxed);
        });
        siv.add_layer(dialog.with_name("pam_dialog"));
    }));
}

fn get_username() -> anyhow::Result<String> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())?;
    let user = user.context("User info not found with current uid")?;
    Ok(user.name)
}

fn pop_pam_msg_dialog(siv: &mut Cursive) {
    if siv.find_name::<Dialog>("pam_dialog").is_some() {
        siv.pop_layer();
    }
}
