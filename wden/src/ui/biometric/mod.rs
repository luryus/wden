use cursive::{Cursive, views::Dialog};

pub fn start_verify_biometric_auth<F: FnOnce(&mut Cursive, bool) + Send + 'static>(
    cursive: &mut Cursive,
    callback: F,
) -> anyhow::Result<()> {
    if cfg!(target_os = "linux") {
        linux_biometric::start_verify_biometric_auth(cursive, callback)
    } else {
        let dialog =
            Dialog::text("Biometric unlock not supported on this platform.").button("OK", |siv| {
                siv.pop_layer();
            });
        cursive.add_layer(dialog);
        Ok(())
    }
}

pub fn is_biometric_unlock_supported() -> bool {
    if cfg!(target_os = "linux") {
        linux_biometric::is_biometric_unlock_supported()
    } else {
        false
    }

}

#[cfg(target_os = "linux")]
mod linux_biometric;
