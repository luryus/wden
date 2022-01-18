use std::{collections::HashMap, sync::MutexGuard, time::Duration};

use anyhow::Context;
use lazy_static::lazy_static;
use std::sync::Mutex;
use x11_clipboard::Clipboard;

lazy_static! {
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

    let data = HashMap::from([
        (kde_password_hint_atom, "secret".into()),
        (cb.setter.atoms.utf8_string, s.as_str().into()),
    ]);

    cb.store_many(cb.setter.atoms.clipboard, data)?;

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
