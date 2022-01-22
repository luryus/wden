use cursive::{
    theme::{BaseColor, Color},
    traits::Nameable,
    view::Margins,
    views::{Dialog, EditView, LinearLayout, PaddedView, TextView},
    Cursive,
};

use crate::bitwarden::cipher::{self, CipherError};

use super::{util::cursive_ext::CursiveExt, vault_table, search};

const VIEW_NAME_PASSWORD: &str = "password";

pub fn lock_vault(c: &mut Cursive) {
    // Remove all layers first
    c.clear_layers();

    // Clear all keys from memory, and get stored email
    let ud = c.get_user_data();
    ud.clear_data_for_locking();
    let email = match ud.email.clone() {
        Some(e) => e,
        None => {
            log::warn!("Email was missing while locking");
            "???".to_owned()
        }
    };
    let profile = ud.global_settings.profile.clone();

    // Vault data is left in place, but its all encrypted

    // Show unlock dialog
    c.add_layer(unlock_dialog(&profile, &email));
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
                TextView::new(format!("Signed in user: {}", email))
                    .style(Color::Light(BaseColor::Black)),
            ),
    )
    .title(format!("Vault locked ({})", profile_name))
    .button("Unlock", submit_unlock)
}

fn submit_unlock(c: &mut Cursive) {
    let password = c
        .call_on_name(VIEW_NAME_PASSWORD, |view: &mut EditView| view.get_content())
        .unwrap();

    c.pop_layer();
    c.add_layer(Dialog::text("Unlocking..."));

    // Get stuff from user data
    let user_data = c.get_user_data();
    let iters = user_data.password_hash_iterations.unwrap();
    let email = user_data.email.clone().unwrap();
    let token_key = user_data.token.as_ref().map(|t| &t.key).unwrap();
    let profile = user_data.global_settings.profile.clone();

    let master_key = cipher::create_master_key(&email, &password, iters);
    let master_pw_hash = cipher::create_master_password_hash(&master_key, &password);

    // Verify that the password was correct by checking if token key can be decrypted
    match cipher::decrypt_symmetric_keys(token_key, &master_key) {
        Err(e) => {
            log::warn!("Unlocking failed: {}", e);

            let err_msg = match e {
                CipherError::MacVerificationFailed(_) => {
                    "Unlocking failed: invalid password".to_owned()
                }
                e => format!("Unlocking failed: {}", e),
            };

            let dialog = Dialog::text(err_msg).button("OK", move |siv| {
                siv.pop_layer();
                siv.add_layer(unlock_dialog(&profile, &email));
            });

            c.pop_layer();
            c.add_layer(dialog);
        }
        Ok(_) => {
            // Success, store keys, restore other data and continue
            user_data.master_key = Some(master_key);
            user_data.master_password_hash = Some(master_pw_hash);
            user_data.password_hash_iterations = Some(iters);

            // Search index gets cleared when locking, restore it
            search::update_search_index(user_data);

            vault_table::show_vault(c);
        }
    }
}
