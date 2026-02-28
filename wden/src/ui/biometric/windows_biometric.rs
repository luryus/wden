use anyhow::Context;
use cursive::Cursive;
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};

use crate::ui::util::cursive_ext::CursiveExt;

pub fn start_verify_biometric_auth<F: FnOnce(&mut Cursive, bool) + Send + 'static>(
    cursive: &mut Cursive,
    callback: F,
) -> anyhow::Result<()> {
    // Run the Windows Hello prompt asynchronously so it doesn't block the UI.
    cursive.async_op(
        async move {
            let result = UserConsentVerifier::RequestVerificationAsync(
                &"Unlock wden vault".into(),
            )
            .context("RequestVerificationAsync call failed")?
            .await?;

            Ok::<bool, anyhow::Error>(result == UserConsentVerificationResult::Verified)
        },
        |siv, res: Result<bool, anyhow::Error>| match res {
            Ok(verified) => callback(siv, verified),
            Err(e) => {
                log::error!("Windows Hello error: {:?}", e);
                callback(siv, false);
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
