use cursive::{
    traits::{Boxable, Nameable},
    views::{Dialog, EditView, LinearLayout, Panel, TextView},
    CbSink, Cursive,
};
use std::convert::TryInto;

use crate::bitwarden::{
    self,
    api::{TokenResponse, TwoFactorProviderType},
    cipher::{MasterKey, MasterPasswordHash},
};

use super::{
    data::{ProfileStore, UserData},
    vault_table::vault_view,
};

pub fn login_dialog(saved_email: &Option<String>) -> Dialog {
    let email_field = if let Some(em) = saved_email {
        EditView::new().content(em)
    } else {
        EditView::new()
    };

    let layout = LinearLayout::vertical()
        .child(TextView::new("Email address"))
        .child(email_field.with_name("email").fixed_width(40))
        .child(TextView::new("Password"))
        .child(
            EditView::new()
                .secret()
                .with_name("password")
                .fixed_width(40),
        );
    Dialog::around(layout)
        .title("Log in")
        .button("Submit", move |c| handle_login(c))
}

fn two_factor_dialog(
    types: Vec<TwoFactorProviderType>,
    email: String,
    master_key: MasterKey,
    master_pw_hash: MasterPasswordHash,
) -> Dialog {
    if !types.contains(&TwoFactorProviderType::Authenticator) {
        Dialog::info("Account requires two-factor authentication, but active two-factor methods are not supported.")
    } else {
        Dialog::around(
            LinearLayout::vertical()
                .child(TextView::new("Enter authenticator code:"))
                .child(EditView::new().with_name("authenticator_code")),
        )
        .button("Submit", move |siv| {
            handle_two_factor_submit(siv, email.clone(), master_key, master_pw_hash)
        })
        .dismiss_button("Cancel")
    }
}

fn handle_login(c: &mut cursive::Cursive) {
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

    let (server_url, profile_store) = c
        .user_data()
        .map(|ud: &mut UserData| {
            (
                ud.global_settings.server_url.clone(),
                ud.profile_store.clone(),
            )
        })
        .unwrap();

    tokio::spawn(async move {
        let res = async {
            let (master_key, master_pw_hash) = do_prelogin(&server_url, &email, &password).await?;
            let login_res =
                do_login(&server_url, &email, &master_pw_hash, None, &profile_store).await?;

            Ok((login_res, master_key, master_pw_hash))
        }
        .await;

        handle_login_response(res, cb, email.to_string());
    });
}

fn handle_login_response(
    res: Result<(TokenResponse, MasterKey, MasterPasswordHash), anyhow::Error>,
    cb: CbSink,
    email: String,
) {
    match res {
        Result::Err(e) => {
            let err_msg = format!("Error: {:?}", e);
            cb.send(Box::new(move |c: &mut Cursive| {
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
        Result::Ok((token, master_key, master_pw_hash)) => {
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
                            dat.master_key = Some(master_key);
                            dat.master_password_hash = Some(master_pw_hash);
                            dat.token = Some(t);
                        });
                        do_sync(c);
                    }))
                    .expect("Sending the cursive callback message failed");
                }
                bitwarden::api::TokenResponse::TwoFactorRequired(types) => {
                    cb.send(Box::new(move |c: &mut Cursive| {
                        c.pop_layer();
                        c.add_layer(two_factor_dialog(types, email, master_key, master_pw_hash));
                    }))
                    .expect("sending cursive message failed");
                }
            }
        }
    }
}

fn handle_two_factor_submit(
    c: &mut Cursive,
    email: String,
    master_key: MasterKey,
    master_pw_hash: MasterPasswordHash,
) {
    let code = c
        .call_on_name("authenticator_code", |view: &mut EditView| {
            view.get_content()
        })
        .unwrap()
        .to_string();

    c.pop_layer();
    c.add_layer(Dialog::text("Signing in..."));

    let cb = c.cb_sink().clone();

    let (server_url, profile_store) = c
        .user_data()
        .map(|ud: &mut UserData| {
            (
                ud.global_settings.server_url.clone(),
                ud.profile_store.clone(),
            )
        })
        .unwrap();

    tokio::spawn(async move {
        let res = do_login(
            &server_url,
            &email,
            &master_pw_hash,
            Some((TwoFactorProviderType::Authenticator, &code)),
            &profile_store,
        )
        .await
        .map(|tr| (tr, master_key, master_pw_hash));
        handle_login_response(res, cb, email);
    });
}

async fn do_prelogin(
    server_url: &str,
    email: &str,
    password: &str,
) -> Result<(MasterKey, MasterPasswordHash), anyhow::Error> {
    let client = bitwarden::api::ApiClient::new(server_url);
    let iterations = client.prelogin(&email).await?;
    let master_key = bitwarden::cipher::create_master_key(
        &email.to_lowercase(),
        &password,
        (iterations as u32).try_into().unwrap(),
    );
    let master_pw_hash = bitwarden::cipher::create_master_password_hash(master_key, &password);

    Ok((master_key, master_pw_hash))
}

async fn do_login(
    server_url: &str,
    email: &str,
    master_pw_hash: &MasterPasswordHash,
    second_factor: Option<(TwoFactorProviderType, &str)>,
    profile_store: &ProfileStore,
) -> Result<TokenResponse, anyhow::Error> {
    let client = bitwarden::api::ApiClient::new(server_url);
    let (token_res, save_2nd_factor) =
        if let Some((two_factor_type, two_factor_token)) = second_factor {
            (
                client
                    .get_token(
                        &email,
                        &base64::encode(&master_pw_hash),
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
                    .get_token(&email, &base64::encode(&master_pw_hash), two_factor_param)
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
    let user_data: &UserData = cursive.user_data().expect("User data not present");

    let access_token = user_data
        .token
        .as_ref()
        .map(|tr| tr.access_token.clone())
        .expect("Token not set");

    let server_url = user_data.global_settings.server_url.clone();

    tokio::spawn(async move {
        let client = bitwarden::api::ApiClient::with_token(&server_url, &access_token);
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

    let table = vault_view(ud);
    let panel = Panel::new(table).title("Vault").full_screen();
    c.add_layer(panel);
}
