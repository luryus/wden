use cursive::{
    traits::{Boxable, Nameable},
    view::Margins,
    views::{Dialog, EditView, LinearLayout, PaddedView, Panel, TextView},
    CbSink, Cursive,
};

use crate::bitwarden::{
    self,
    api::{ApiClient, TokenResponse, TwoFactorProviderType},
    cipher::{self, MasterKey, MasterPasswordHash},
};

use super::{
    data::{ProfileStore, UserData},
    vault_table::vault_view,
};

pub fn login_dialog(saved_email: &Option<String>) -> Dialog {
    let password_field = EditView::new()
        .secret()
        .on_submit(|siv, _| submit_login(siv))
        .with_name("password")
        .fixed_width(40);

    let email_field = if let Some(em) = saved_email {
        EditView::new().content(em)
    } else {
        EditView::new()
    };
    let email_field = email_field
        .on_submit(|siv, _| {
            siv.focus_name("password").unwrap();
        })
        .with_name("email")
        .fixed_width(40);

    let layout = LinearLayout::vertical()
        .child(TextView::new("Email address"))
        .child(email_field)
        .child(TextView::new("Password"))
        .child(password_field);
    Dialog::around(layout)
        .title("Log in")
        .button("Submit", |c| submit_login(c))
}

fn two_factor_dialog(types: Vec<TwoFactorProviderType>, email: String) -> Dialog {
    if !types.contains(&TwoFactorProviderType::Authenticator) {
        Dialog::info("Account requires two-factor authentication, but active two-factor methods are not supported.")
    } else {
        Dialog::around(
            LinearLayout::vertical()
                .child(TextView::new("Enter authenticator code:"))
                .child(EditView::new().with_name("authenticator_code")),
        )
        .button("Submit", move |siv| submit_two_factor(siv, email.clone()))
        .dismiss_button("Cancel")
    }
}

pub fn lock_vault(c: &mut Cursive) {
    // Remove all layers first
    while c.pop_layer().is_some() {}

    // Clear all keys from memory, and get stored email
    let email = c
        .with_user_data(|ud: &mut UserData| {
            ud.clear_data_for_locking();
            ud.email.clone()
        })
        .flatten();
    let email = match email.as_ref() {
        Some(e) => e,
        None => {
            log::warn!("Email was missing while locking");
            "???"
        }
    };

    // Vault data is left in place, but its all encrypted

    // Show unlock dialog
    c.add_layer(unlock_dialog(email));
}

fn unlock_dialog(email: &str) -> Dialog {
    let pw_editview = EditView::new()
        .secret()
        .on_submit(|siv, _| submit_unlock(siv))
        .with_name("password");

    Dialog::around(
        LinearLayout::vertical()
            .child(TextView::new(format!(
                "Vault is locked (account {}). Unlock with master password:",
                email
            )))
            .child(PaddedView::new(Margins::tb(1, 1), pw_editview)),
    )
    .button("Unlock", |siv| submit_unlock(siv))
}

fn submit_unlock(c: &mut Cursive) {
    let password = c
        .call_on_name("password", |view: &mut EditView| view.get_content())
        .unwrap();

    c.pop_layer();
    c.add_layer(Dialog::text("Unlocking..."));

    // Get stuff from user data
    let user_data: &mut UserData = c.user_data().unwrap();
    let iters = user_data.password_hash_iterations.unwrap();
    let email = user_data.email.clone().unwrap();
    let token_key = user_data.token.as_ref().map(|t| &t.key).unwrap();

    let (master_key, master_pw_hash) = get_master_key_pw_hash(&email, &password, iters);

    // Verify that the password was correct by checking if token key can be decrypted
    match cipher::decrypt_symmetric_keys(token_key, &master_key) {
        Err(e) => {
            log::error!("Unlocking failed: {}", e);
            c.pop_layer();
            c.add_layer(
                Dialog::text(format!("Unlocking failed: {}", e)).button("OK", move |siv| {
                    siv.pop_layer();
                    siv.add_layer(unlock_dialog(&email));
                }),
            )
        }
        Ok(_) => {
            // Success, store keys and continue
            user_data.master_key = Some(master_key);
            user_data.master_password_hash = Some(master_pw_hash);
            user_data.password_hash_iterations = Some(iters);

            c.pop_layer();
            show_item_list(c);
        }
    }
}

fn submit_login(c: &mut Cursive) {
    let email = c
        .call_on_name("email", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();
    let password = c
        .call_on_name("password", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();

    c.pop_layer();
    c.add_layer(Dialog::text("Signing in..."));

    let cb = c.cb_sink().clone();

    let (server_url, device_id, profile_store) = c
        .user_data()
        .map(|ud: &mut UserData| {
            (
                ud.global_settings.server_url.clone(),
                ud.global_settings.device_id.clone(),
                ud.profile_store.clone(),
            )
        })
        .unwrap();

    tokio::spawn(async move {
        let res = async {
            let (master_key, master_pw_hash, iterations) =
                do_prelogin(&server_url, device_id.clone(), &email, &password).await?;

            let store_pw_hash = master_pw_hash.clone();
            cb.send(Box::new(move |c: &mut Cursive| {
                let mut ud: &mut UserData = c.user_data().unwrap();
                ud.master_key = Some(master_key);
                ud.master_password_hash = Some(store_pw_hash);
                ud.password_hash_iterations = Some(iterations);
            }))
            .expect("Failed to send callback");

            do_login(&server_url, device_id, &email, &master_pw_hash, None, &profile_store).await
        }
        .await;

        handle_login_response(res, cb, email.to_string());
    });
}

fn handle_login_response(res: Result<TokenResponse, anyhow::Error>, cb: CbSink, email: String) {
    match res {
        Result::Err(e) => {
            let err_msg = format!("Error: {:?}", e);
            cb.send(Box::new(move |c: &mut Cursive| {
                c.with_user_data(|ud: &mut UserData| {
                    ud.clear_login_data();
                });
                c.add_layer(
                    Dialog::text(err_msg)
                        .title("Login error")
                        .button("OK", move |siv| {
                            // Remove this dialog, and show the login dialog again
                            siv.pop_layer();
                            siv.add_layer(login_dialog(&Some(email.clone())));
                        }),
                );
            }))
            .expect("Sending the cursive callback message failed");
        }
        Result::Ok(token) => {
            match token {
                bitwarden::api::TokenResponse::Success(t) => {
                    cb.send(Box::new(move |c: &mut Cursive| {
                        c.pop_layer();
                        c.with_user_data(|dat: &mut UserData| {
                            // Try to store the email
                            let store_res = dat
                                .profile_store
                                .edit(|d| d.saved_email = Some(email.clone()));
                            if let Err(e) = store_res {
                                log::error!("Failed to store profile data: {}", e);
                            }

                            dat.email = Some(email);
                            dat.token = Some(t);
                        });
                        do_sync(c);
                    }))
                    .expect("Sending the cursive callback message failed");
                }
                bitwarden::api::TokenResponse::TwoFactorRequired(types) => {
                    cb.send(Box::new(move |c: &mut Cursive| {
                        c.pop_layer();
                        c.add_layer(two_factor_dialog(types, email));
                    }))
                    .expect("sending cursive message failed");
                }
            }
        }
    }
}

fn submit_two_factor(c: &mut Cursive, email: String) {
    let code = c
        .call_on_name("authenticator_code", |view: &mut EditView| {
            view.get_content()
        })
        .unwrap()
        .to_string();

    c.pop_layer();
    c.add_layer(Dialog::text("Signing in..."));

    let cb = c.cb_sink().clone();

    let (server_url, device_id, profile_store) = c
        .user_data()
        .map(|ud: &mut UserData| {
            (
                ud.global_settings.server_url.clone(),
                ud.global_settings.device_id.clone(),
                ud.profile_store.clone(),
            )
        })
        .unwrap();

    // Have to clone the hash here, because it's not
    // really possible to access user_data inside the async
    // block in any good form
    let master_pw_hash = c
        .with_user_data(|ud: &mut UserData| ud.master_password_hash.clone())
        .flatten()
        .unwrap();

    tokio::spawn(async move {
        let res = do_login(
            &server_url,
            device_id,
            &email,
            &master_pw_hash,
            Some((TwoFactorProviderType::Authenticator, &code)),
            &profile_store,
        )
        .await;
        handle_login_response(res, cb, email);
    });
}

fn get_master_key_pw_hash(
    email: &str,
    password: &str,
    iterations: u32,
) -> (MasterKey, MasterPasswordHash) {
    let master_key = bitwarden::cipher::create_master_key(
        &email.to_lowercase(),
        password,
        iterations,
    );
    let master_pw_hash = bitwarden::cipher::create_master_password_hash(&master_key, password);

    (master_key, master_pw_hash)
}

async fn do_prelogin(
    server_url: &str,
    device_identifier: String,
    email: &str,
    password: &str,
) -> Result<(MasterKey, MasterPasswordHash, u32), anyhow::Error> {
    let client = bitwarden::api::ApiClient::new(server_url, device_identifier);
    let iterations = client.prelogin(email).await?;
    let (master_key, master_pw_hash) = get_master_key_pw_hash(email, password, iterations);
    Ok((master_key, master_pw_hash, iterations))
}

async fn do_login(
    server_url: &str,
    device_identifier: String,
    email: &str,
    master_pw_hash: &MasterPasswordHash,
    second_factor: Option<(TwoFactorProviderType, &str)>,
    profile_store: &ProfileStore,
) -> Result<TokenResponse, anyhow::Error> {
    let client = bitwarden::api::ApiClient::new(server_url, device_identifier);
    let (token_res, save_2nd_factor) =
        if let Some((two_factor_type, two_factor_token)) = second_factor {
            (
                client
                    .get_token(
                        email,
                        &master_pw_hash.base64_encoded(),
                        Some((two_factor_type, two_factor_token, true)),
                    )
                    .await?,
                true,
            )
        } else {
            // Try to read stored 2nd factor token
            let two_factor_param = profile_store
                .load()
                .ok()
                .and_then(|d| d.saved_two_factor_token);

            let two_factor_param = two_factor_param
                .as_ref()
                .map(|t| Some((TwoFactorProviderType::Remember, t.as_str(), false)))
                .unwrap_or(None);

            (
                client
                    .get_token(email, &master_pw_hash.base64_encoded(), two_factor_param)
                    .await?,
                false,
            )
        };

    if let bitwarden::api::TokenResponse::Success(t) = &token_res {
        if save_2nd_factor {
            profile_store
                .edit(|d| d.saved_two_factor_token = t.two_factor_token.clone())
                .expect("Storing 2nd factor token failed");
        }
    }

    Ok(token_res)
}

pub fn do_sync(cursive: &mut Cursive) {
    // Remove all layers first
    while cursive.pop_layer().is_some() {}
    cursive.add_layer(Dialog::text("Syncing..."));
    let ccb = cursive.cb_sink().clone();
    let user_data: &mut UserData = cursive.user_data().expect("User data not present");

    // Clear any data remaining
    user_data.vault_data = None;
    user_data.vault_table_rows = None;
    user_data.organizations = None;
    user_data.autolocker.lock().unwrap().clear_autolock_time();

    let email = user_data.email.clone().unwrap();

    let (access_token, should_refresh, refresh_token) = user_data
        .token
        .as_ref()
        .map(|tr| {
            (
                tr.access_token.clone(),
                tr.should_refresh(),
                tr.refresh_token.clone(),
            )
        })
        .expect("Token not set");

    let server_url = user_data.global_settings.server_url.clone();
    let device_id = user_data.global_settings.device_id.clone();

    tokio::spawn(async move {
        if should_refresh {
            log::debug!("Refreshing token");
            let client = ApiClient::new(&server_url, device_id.clone());
            let refresh_res = client.refresh_token(&refresh_token).await;

            handle_login_response(refresh_res, ccb, email);
            return;
        }

        let client = ApiClient::with_token(&server_url, device_id, &access_token);
        let sync_res = client.sync().await;

        match sync_res {
            Ok(sync_res) => {
                ccb.send(Box::new(move |c: &mut Cursive| {
                    c.with_user_data(|ud: &mut UserData| {
                        ud.vault_data = Some(
                            sync_res
                                .ciphers
                                .into_iter()
                                .map(|ci| (ci.id.clone(), ci))
                                .collect(),
                        );
                        ud.organizations = Some(
                            sync_res
                                .profile
                                .organizations
                                .into_iter()
                                .map(|o| (o.id.clone(), o))
                                .collect(),
                        );
                    });
                    c.pop_layer();
                    show_item_list(c);
                }))
                .expect("Sending cursive callback failed");
            }
            Err(sync_err) => {
                ccb.send(Box::new(move |c: &mut Cursive| {
                    let err_msg = format!("Error syncing: {}", sync_err);
                    c.add_layer(Dialog::around(TextView::new(err_msg)));
                }))
                .expect("Sending cursive callback failed");
            }
        }
    });
}

fn show_item_list(c: &mut Cursive) {
    let ud: &mut UserData = c.user_data().unwrap();
    ud.autolocker
        .lock()
        .unwrap()
        .update_next_autolock_time(true);

    let table = vault_view(ud);
    let panel = Panel::new(table).title("Vault").full_screen();
    c.add_fullscreen_layer(panel);
}
