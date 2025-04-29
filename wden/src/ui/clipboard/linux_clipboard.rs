use std::sync::OnceLock;

use super::{PlatformClipboard, PlatformClipboardResult};

#[derive(PartialEq, Eq)]
enum LinuxClipboardPlatform {
    X11,
    Wayland,
}
pub struct LinuxClipboard;

fn get_cb_impl() -> &'static LinuxClipboardPlatform {
    static LINUX_CB_IMPL: OnceLock<LinuxClipboardPlatform> = OnceLock::new();
    LINUX_CB_IMPL.get_or_init(|| {
        if wayland::is_available() {
            LinuxClipboardPlatform::Wayland
        } else {
            LinuxClipboardPlatform::X11
        }
    })
}

impl PlatformClipboard for LinuxClipboard {
    fn clip_string(s: String) -> PlatformClipboardResult<()> {
        if get_cb_impl() == &LinuxClipboardPlatform::X11 {
            log::info!("Clipping using x11");
            x11::clip_string(s)
        } else {
            log::info!("Clipping using wayland");
            wayland::clip_string(s)
        }
    }

    fn get_string_contents() -> PlatformClipboardResult<String> {
        if get_cb_impl() == &LinuxClipboardPlatform::X11 {
            x11::get_string_contents()
        } else {
            wayland::get_string_contents()
        }
    }

    fn clear() -> PlatformClipboardResult<()> {
        if get_cb_impl() == &LinuxClipboardPlatform::X11 {
            x11::clip_string(String::new())
        } else {
            wayland::clear()
        }
    }
}

mod x11 {
    use super::PlatformClipboardResult;
    use anyhow::Context;
    use lazy_static::lazy_static;
    use std::collections::HashMap;
    use std::{
        sync::{Mutex, MutexGuard},
        time::Duration,
    };

    use x11_clipboard::{Atom, Clipboard};
    use x11rb::{connection::Connection, protocol::xproto::ConnectionExt};

    lazy_static! {
        static ref CLIPBOARD: Mutex<Option<Clipboard>> = Mutex::new(None);
    }

    pub fn _is_available() -> bool {
        get_cb().is_ok()
    }

    pub fn clip_string(s: String) -> PlatformClipboardResult<()> {
        let cb = get_cb()?;

        let cb = cb.as_ref().unwrap();
        let kde_password_hint_atom = get_kde_password_hint_atom(&cb.setter.connection)?;

        let data = HashMap::from([
            (kde_password_hint_atom, "secret".into()),
            (cb.setter.atoms.utf8_string, s.as_str().into()),
        ]);

        cb.store_many(cb.setter.atoms.clipboard, data)?;

        Ok(())
    }

    pub fn get_string_contents() -> PlatformClipboardResult<String> {
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

    fn get_cb() -> Result<MutexGuard<'static, Option<Clipboard>>, anyhow::Error> {
        let mut cb_opt = CLIPBOARD.lock().unwrap();
        if cb_opt.is_none() {
            *cb_opt = Some(Clipboard::new()?);
        }

        Ok(cb_opt)
    }

    fn get_kde_password_hint_atom(connection: &impl Connection) -> PlatformClipboardResult<Atom> {
        let cookie = connection.intern_atom(false, b"x-kde-passwordManagerHint")?;
        Ok(cookie.reply()?.atom)
    }
}

mod wayland {

    use anyhow::Context;
    use std::io::Read;
    use wl_clipboard_rs::{
        copy,
        copy::{MimeSource, Options, Source},
        paste,
        paste::{ClipboardType, Error, Seat, get_contents},
    };

    use super::PlatformClipboardResult;

    pub fn get_string_contents() -> PlatformClipboardResult<String> {
        let res = get_contents(
            ClipboardType::Regular,
            Seat::Unspecified,
            paste::MimeType::Text,
        );
        match res {
            Ok((mut pipe, _mime_type)) => {
                let mut buf = vec![];
                pipe.read_to_end(&mut buf)?;
                Ok(String::from_utf8_lossy(&buf).into_owned())
            }

            Err(Error::NoSeats) | Err(Error::ClipboardEmpty) | Err(Error::NoMimeType) => {
                // This can be considered as empty
                Ok(String::new())
            }

            Err(e) => Err(e).context("Getting wayland clipboard failed"),
        }
    }

    pub fn clip_string(s: String) -> PlatformClipboardResult<()> {
        let opts = Options::new();

        let data = vec![
            MimeSource {
                source: Source::Bytes(s.as_bytes().into()),
                mime_type: copy::MimeType::Text,
            },
            MimeSource {
                source: Source::Bytes("secret".as_bytes().into()),
                mime_type: kde_password_hint_mime_type(),
            },
        ];

        opts.copy_multi(data).context("Copying failed")
    }

    pub fn kde_password_hint_mime_type() -> copy::MimeType {
        copy::MimeType::Specific("x-kde-passwordManagerHint".into())
    }

    pub fn clear() -> PlatformClipboardResult<()> {
        copy::clear(copy::ClipboardType::Regular, copy::Seat::All).context("Clearing failed")
    }

    pub fn is_available() -> bool {
        let res = get_contents(
            ClipboardType::Regular,
            Seat::Unspecified,
            paste::MimeType::Any,
        );

        log::info!("Wayland res: {:?}", res);

        matches!(
            res,
            Ok(_) | Err(Error::ClipboardEmpty) | Err(Error::NoMimeType)
        )
    }
}
