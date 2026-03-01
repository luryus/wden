use std::sync::Arc;

use anyhow::Context;
use cursive::{
    Cursive,
    theme::{BaseColor, Color},
    traits::Nameable,
    view::Margins,
    views::{Dialog, EditView, LinearLayout, NamedView, PaddedView, TextView},
};
use serde::{Deserialize, Serialize};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    bitwarden::{
        api::TokenResponseSuccess,
        cipher::{self, Cipher, CipherError, EncMacKeys, MasterKey},
    },
    ui::{biometric, util::cursive_ext::CursiveErrorExt},
    util::{keystore, slice_writer::SliceWriter},
};

use super::{util::cursive_ext::CursiveExt, vault_table};

const VIEW_NAME_PASSWORD: &str = "password";
const VIEW_NAME_BIOMETRIC_ERROR: &str = "biometric_error";
const VIEW_NAME_UNLOCK_DIALOG: &str = "unlock_dialog";

const LOCK_DATA_SERIALIZED_MAX_SIZE: usize = 16_000;

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct EncryptedLockData {
    search_filter: String,
    token: TokenResponseSuccess,
    master_key: Option<MasterKey>,
}

impl EncryptedLockData {
    pub fn encrypt(&self, keys: &EncMacKeys) -> anyhow::Result<Cipher> {
        // Use a static size buffer to try to keep zeroizing effective
        let mut buf = Zeroizing::new([0u8; LOCK_DATA_SERIALIZED_MAX_SIZE]);
        let mut writer = SliceWriter::new(buf.as_mut_slice());
        serde_json::to_writer(&mut writer, self)?;
        let written = writer.written_len();

        let data = &buf[..written];
        let enc = Cipher::encrypt(data, keys)?;

        Ok(enc)
    }

    pub fn decrypt_from(cipher: &Cipher, keys: &EncMacKeys) -> anyhow::Result<Self> {
        let mut buf = Zeroizing::new([0u8; LOCK_DATA_SERIALIZED_MAX_SIZE]);
        let decrypted_buf = cipher
            .decrypt_to(keys, buf.as_mut_slice())
            .context("Decrypting locked data failed")?;

        serde_json::from_slice(decrypted_buf).context("Deserializing lock data failed")
    }
}

pub fn lock_vault(c: &mut Cursive) -> anyhow::Result<()> {
    if c.get_user_data().with_locked_state().is_some() {
        // Already locked
        return Ok(());
    }

    // Get the search term, we will want to restore it after unlocking
    let (search_term, collection_selection) = vault_table::get_filters(c).unwrap_or_default();

    // Remove all layers
    c.clear_layers();

    let ud = c
        .get_user_data()
        .with_unlocked_state()
        .expect("The app state should be 'Unlocked' when trying to lock");

    // Generate a new key and encrypt the lock data with it. This intermediate key
    // allows us to support both password-based and biometric unlock.
    let use_biometric =
        ud.global_settings().use_biometric_unlock && biometric::is_biometric_unlock_supported();

    let lock_key = EncMacKeys::secure_generate();
    let enc_lock_data = EncryptedLockData {
        search_filter: search_term,
        token: ud.get_token_object().clone(),
        master_key: use_biometric.then_some(ud.master_key().clone()),
    }
    .encrypt(&lock_key)?;

    // Then serialize and encrypt the lock key with the user's own key, this can be used
    // for password unlock
    let user_keys = ud
        .decrypt_keys()
        .context("Decrypting user keys failed while locking")?;
    let user_encrypted_lock_key = lock_key
        .encrypt_serialized(&user_keys)
        .context("Encrypting lock key with user keys failed")?;

    let keystore = if use_biometric {
        // Store the unlock key to the system keystore where it can be retrieved later for biometric unlock
        let res = keystore::get_platform_keystore().and_then(|ks| {
            ks.borrow_mut().store_enc_mac_keys(&lock_key)?;
            Ok(ks)
        });

        match res {
            Ok(ks) => Some(ks),
            Err(e) => {
                log::warn!("Error storing key for biometric unlock: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    // Clear all keys from memory, and get stored email
    let ud = ud.into_locked(
        enc_lock_data,
        user_encrypted_lock_key,
        keystore,
        collection_selection,
    );
    let global_settings = ud.global_settings();
    let profile = global_settings.profile.as_str();
    let email = ud.email();
    // Vault data is left in place, but it's all encrypted

    // Show unlock dialog
    let d = unlock_dialog(profile, &email, ud.has_biometric_keys());
    c.add_layer(d);
    Ok(())
}

fn unlock_dialog(profile_name: &str, email: &str, biometric: bool) -> NamedView<Dialog> {
    let pw_editview = EditView::new()
        .secret()
        .on_submit(|siv, _| submit_unlock(siv))
        .with_name(VIEW_NAME_PASSWORD);

    let mut dialog = Dialog::around(
        LinearLayout::vertical()
            .child(TextView::new(
                "Vault is locked. Unlock with master password:",
            ))
            .child(PaddedView::new(Margins::tb(1, 1), pw_editview))
            .child(
                TextView::new(format!("Signed in as: {email}"))
                    .style(Color::Light(BaseColor::Black)),
            )
            .child(
                TextView::new(String::default())
                    .style(Color::Dark(BaseColor::Red))
                    .with_name(VIEW_NAME_BIOMETRIC_ERROR),
            ),
    )
    .title(format!("Vault locked ({profile_name})"));

    if biometric {
        dialog = dialog.button("Biometric unlock", start_biometric_unlock)
    }
    dialog = dialog.button("Unlock", submit_unlock);

    dialog.with_name(VIEW_NAME_UNLOCK_DIALOG)
}

fn start_biometric_unlock(c: &mut Cursive) {
    let res = biometric::start_verify_biometric_auth(c, |siv, success| {
        if success {
            unlock_with_biometric_keys(siv);
        } else {
            let mut error_label = siv
                .find_name::<TextView>(VIEW_NAME_BIOMETRIC_ERROR)
                .unwrap();
            error_label.set_content("Error unlocking the vault using biometrics.\nPlease unlock using the master password.");
            let mut unlock_dialog = siv.find_name::<Dialog>(VIEW_NAME_UNLOCK_DIALOG).unwrap();
            unlock_dialog.remove_button(0);
        }
    });
    if let Err(e) = res {
        e.fatal_err_dialog(c);
    }
}

fn submit_unlock(c: &mut Cursive) {
    let password = c
        .call_on_name(VIEW_NAME_PASSWORD, |view: &mut EditView| view.get_content())
        .unwrap();

    c.pop_layer();
    c.add_layer(Dialog::text("Unlocking..."));

    // Get stuff from user data
    let user_data = c.get_user_data().with_locked_state().unwrap();
    let global_settings = user_data.global_settings().clone();
    let pbkdf = user_data.pbkdf();
    let email = user_data.email().clone();
    let token_key = user_data.encrypted_user_key();
    let api_key = user_data.api_key();
    let biometric = user_data.has_biometric_keys();

    let keys_res = derive_and_check_master_key(&email, password.as_bytes(), &pbkdf, token_key);

    match keys_res {
        Err(e) => {
            log::warn!("Unlocking failed: {e}");

            let err_msg = match e {
                CipherError::MacVerificationFailed(_) => {
                    "Unlocking failed: invalid password".to_owned()
                }
                e => format!("Unlocking failed: {e}"),
            };

            let dialog = Dialog::text(err_msg).button("OK", move |siv| {
                siv.pop_layer();
                siv.add_layer(unlock_dialog(&global_settings.profile, &email, biometric));
            });

            c.pop_layer();
            c.add_layer(dialog);
        }
        Ok(master_key) => {
            // Success. Decrypt the lock key, and then decrypt the lock data using that.
            let user_data = user_data.into_unlocking(master_key, api_key);

            match user_data.decrypt_lock_data() {
                Ok(mut lock_data) => {
                    let collection_selection = user_data.collection_selection();
                    let _ = user_data.into_unlocked(Arc::new(lock_data.token.clone()));

                    vault_table::show_vault_with_filters(
                        c,
                        std::mem::take(&mut lock_data.search_filter),
                        collection_selection,
                    );
                }
                Err(e) => e.fatal_err_dialog(c),
            }
        }
    }
}

fn derive_and_check_master_key(
    email: &Arc<String>,
    password: &[u8],
    pbkdf: &Arc<cipher::PbkdfParameters>,
    token_key: &cipher::Cipher,
) -> Result<Arc<cipher::MasterKey>, CipherError> {
    let master_key = Arc::new(cipher::create_master_key(email, password, pbkdf)?);
    // Verify that the password was correct by checking if token key can be decrypted
    let _ = cipher::decrypt_symmetric_keys(token_key, &master_key)?;
    Ok(master_key)
}

fn unlock_with_biometric_keys(cursive: &mut Cursive) {
    cursive.pop_layer();
    cursive.add_layer(Dialog::text("Unlocking..."));

    // Get stuff from user data
    let user_data = cursive.get_user_data().with_locked_state().unwrap();
    let api_key = user_data.api_key();

    let res = (|| -> anyhow::Result<_> {
        let keystore = user_data
            .keystore()
            .context("Keystore was not set while unlocking biometrics")?;
        let lock_key = keystore
            .borrow_mut()
            .retrieve_enc_mac_keys()
            .context("Retrieving biometric key failed")?;
        let mut lock_data =
            EncryptedLockData::decrypt_from(user_data.encrypted_lock_data(), &lock_key)
                .context("Decrypting lock data failed")?;
        let master_key = lock_data
            .master_key
            .take()
            .context("Master key was not stored in lock data")?;
        Ok((lock_data, master_key))
    })();

    match res {
        Err(e) => {
            log::warn!("Biometric unlock failed: {e:?}");
            e.fatal_err_dialog(cursive);
        }
        Ok((mut lock_data, master_key)) => {
            let master_key = Arc::new(master_key);
            let user_data = user_data.into_unlocking(master_key, api_key);

            let collection_selection = user_data.collection_selection();
            let _ = user_data.into_unlocked(Arc::new(lock_data.token.clone()));

            vault_table::show_vault_with_filters(
                cursive,
                std::mem::take(&mut lock_data.search_filter),
                collection_selection,
            );
        }
    }
}
