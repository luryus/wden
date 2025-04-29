use std::sync::Arc;

use cursive::{
    Cursive,
    theme::{BaseColor, Color},
    traits::Nameable,
    view::Margins,
    views::{Dialog, EditView, LinearLayout, PaddedView, TextView},
};

use crate::bitwarden::cipher::{self, CipherError};

use super::{util::cursive_ext::CursiveExt, vault_table};

const VIEW_NAME_PASSWORD: &str = "password";

pub fn lock_vault(c: &mut Cursive) {
    if c.get_user_data().with_locked_state().is_some() {
        // Already locked
        return;
    }

    // Get the search term, we want to restore it after unlocking
    let (search_term, collection_selection) = vault_table::get_filters(c).unwrap_or_default();

    // Remove all layers
    c.clear_layers();

    // Clear all keys from memory, and get stored email
    let ud = c
        .get_user_data()
        .with_unlocked_state()
        .expect("The app state should be 'Unlocked' when trying to lock")
        .into_locked(&search_term, collection_selection);
    let global_settings = ud.global_settings();
    let profile = global_settings.profile.as_str();
    let email = ud.email();

    // Vault data is left in place, but it's all encrypted

    // Show unlock dialog
    let d = unlock_dialog(profile, &email);
    c.add_layer(d);
}

fn unlock_dialog(profile_name: &str, email: &str) -> Dialog {
    let pw_editview = EditView::new()
        .secret()
        .on_submit(|siv, _| submit_unlock(siv))
        .with_name(VIEW_NAME_PASSWORD);

    Dialog::around(
        LinearLayout::vertical()
            .child(TextView::new(
                "Vault is locked. Unlock with master password:",
            ))
            .child(PaddedView::new(Margins::tb(1, 1), pw_editview))
            .child(
                TextView::new(format!("Signed in user: {email}"))
                    .style(Color::Light(BaseColor::Black)),
            ),
    )
    .title(format!("Vault locked ({profile_name})"))
    .button("Unlock", submit_unlock)
}

fn submit_unlock(c: &mut Cursive) {
    let password = c
        .call_on_name(VIEW_NAME_PASSWORD, |view: &mut EditView| view.get_content())
        .unwrap();

    c.pop_layer();
    c.add_layer(Dialog::text("Unlocking..."));

    // Get stuff from user data
    let user_data = c.get_user_data().with_locked_state().unwrap();
    let global_settings = user_data.global_settings();
    let pbkdf = user_data.pbkdf();
    let email = user_data.email();
    let token_key = &user_data.token().key;
    let api_key = user_data.api_key();

    let keys_res = derive_and_check_master_key(&email, &password, &pbkdf, token_key);

    match keys_res {
        Err(e) => {
            log::warn!("Unlocking failed: {}", e);

            let err_msg = match e {
                CipherError::MacVerificationFailed(_) => {
                    "Unlocking failed: invalid password".to_owned()
                }
                e => format!("Unlocking failed: {e}"),
            };

            let dialog = Dialog::text(err_msg).button("OK", move |siv| {
                siv.pop_layer();
                siv.add_layer(unlock_dialog(&global_settings.profile, &email));
            });

            c.pop_layer();
            c.add_layer(dialog);
        }
        Ok(master_key) => {
            // Success, store keys, restore other data and continue
            let user_data = user_data.into_unlocking(master_key, api_key);

            let search_term = user_data.decrypt_search_term().unwrap_or_default();
            let collection_selection = user_data.collection_selection();
            let _ = user_data.into_unlocked();

            vault_table::show_vault_with_filters(c, search_term, collection_selection);
        }
    }
}

fn derive_and_check_master_key(
    email: &Arc<String>,
    password: &Arc<String>,
    pbkdf: &Arc<cipher::PbkdfParameters>,
    token_key: &cipher::Cipher,
) -> Result<Arc<cipher::MasterKey>, CipherError> {
    let master_key = Arc::new(cipher::create_master_key(email, password, pbkdf)?);
    // Verify that the password was correct by checking if token key can be decrypted
    let _ = cipher::decrypt_symmetric_keys(token_key, &master_key)?;
    Ok(master_key)
}
