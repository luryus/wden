use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::Context;
use cursive::{Cursive, view::Nameable, views::Dialog};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};

use crate::ui::util::cursive_ext::{CursiveCallbackExt, CursiveExt};

const HELLO_DIALOG_NAME: &str = "hello_in_progress";

pub fn start_verify_biometric_auth<F: FnOnce(&mut Cursive, bool) + Send + 'static>(
    cursive: &mut Cursive,
    callback: F,
) -> anyhow::Result<()> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let cb_sink = cursive.cb_sink().clone();

    // Show a "Windows Hello in progress" dialog so the user knows what's happening
    // and to prevent them from clicking the biometric button again
    {
        let cancel_flag = Arc::clone(&cancelled);
        cb_sink.send_msg(Box::new(move |siv| {
            let dialog = Dialog::text("Waiting for Windows Hello verification...").button(
                "Cancel",
                move |siv| {
                    siv.pop_layer();
                    cancel_flag.store(true, Ordering::Relaxed);
                },
            );
            siv.add_layer(dialog.with_name(HELLO_DIALOG_NAME));
        }));
    }

    // Run the Windows Hello prompt asynchronously so it doesn't block the UI.
    cursive.async_op(
        async move {
            let result = UserConsentVerifier::RequestVerificationAsync(&"Unlock wden vault".into())
                .context("RequestVerificationAsync call failed")?
                .await?;

            Ok::<bool, anyhow::Error>(result == UserConsentVerificationResult::Verified)
        },
        move |siv, res: Result<bool, anyhow::Error>| {
            // Remove the progress dialog if it's still there
            if siv.find_name::<Dialog>(HELLO_DIALOG_NAME).is_some() {
                siv.pop_layer();
            }

            // Don't execute callback if user cancelled while we were waiting
            if cancelled.load(Ordering::Relaxed) {
                return;
            }

            match res {
                Ok(verified) => callback(siv, verified),
                Err(e) => {
                    log::error!("Windows Hello error: {:?}", e);
                    callback(siv, false);
                }
            }
        },
    );

    Ok(())
}

pub fn is_biometric_unlock_supported() -> bool {
    let result = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let availability = UserConsentVerifier::CheckAvailabilityAsync()
                .context("CheckAvailabilityAsync call failed")?
                .await?;

            log::info!("Windows Hello availability: {:?}", availability);

            Ok::<bool, anyhow::Error>(availability == UserConsentVerifierAvailability::Available)
        })
    });

    match result {
        Ok(available) => available,
        Err(e) => {
            log::warn!("Error checking Windows Hello availability: {:?}", e);
            false
        }
    }
}
