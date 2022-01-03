use std::{time::Duration, sync::MutexGuard};

use anyhow::Context;
use x11_clipboard::Clipboard;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static!{
    static ref CLIPBOARD: Mutex<Option<Clipboard>> = Mutex::new(None);
}

fn get_cb() -> Result<MutexGuard<'static, Option<Clipboard>>, anyhow::Error> {
    let mut cb_opt = CLIPBOARD.lock().unwrap();
    if cb_opt.is_none() {
        *cb_opt = Some(Clipboard::new()?);
    }

    Ok(cb_opt)
}

pub fn clip_string_internal(s: String) -> Result<(), anyhow::Error> {
    let cb = get_cb()?;

    let cb = cb.as_ref().unwrap();
    let kde_password_hint_atom =
        x11_clipboard::xcb::intern_atom(&cb.setter.connection, false, "x-kde-passwordManagerHint")
            .get_reply()?
            .atom();
    cb.store(cb.setter.atoms.clipboard, kde_password_hint_atom, "secret")?;
    cb.store(
        cb.setter.atoms.clipboard,
        cb.setter.atoms.utf8_string,
        s.as_str(),
    )?;

    log::info!("Stored \"{}\" to clipboard", s);

    Ok(())
}

pub fn get_string_contents_internal() -> Result<String, anyhow::Error> {
    let cb = get_cb()?;

    let cb = cb.as_ref().unwrap();
    let val = cb.load(
        cb.setter.atoms.clipboard,
        cb.setter.atoms.utf8_string,
        cb.setter.atoms.property,
        Duration::from_secs(3),
    )?;

    String::from_utf8(val).context("Parsing UTF-8 string failed")
}
