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

#[cfg(target_os = "linux")]
mod linux_biometric;
