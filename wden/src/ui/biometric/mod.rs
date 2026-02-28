use cursive::Cursive;

#[cfg(target_os = "linux")]
mod linux_biometric;
#[cfg(windows)]
mod windows_biometric;

pub fn start_verify_biometric_auth<F: FnOnce(&mut Cursive, bool) + Send + 'static>(
    cursive: &mut Cursive,
    callback: F,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux_biometric::start_verify_biometric_auth(cursive, callback)
    }

    #[cfg(windows)]
    {
        windows_biometric::start_verify_biometric_auth(cursive, callback)
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        use cursive::views::Dialog;
        let dialog =
            Dialog::text("Biometric unlock not supported on this platform.").button("OK", |siv| {
                siv.pop_layer();
            });
        cursive.add_layer(dialog);
        Ok(())
    }
}

pub fn is_biometric_unlock_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux_biometric::is_biometric_unlock_supported()
    }

    #[cfg(windows)]
    {
        windows_biometric::is_biometric_unlock_supported()
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        false
    }
}
