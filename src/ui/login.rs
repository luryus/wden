use std::sync::Arc;

use cursive::{
    traits::{Nameable, Resizable},
    views::{Dialog, EditView, LinearLayout, TextView},
    CbSink, Cursive,
};

use crate::bitwarden::{
    self,
    api::{ApiClient, TokenResponse, TwoFactorProviderType},
    cipher::{self, MasterKey, MasterPasswordHash},
};

use super::{
    data::ProfileStore,
    sync::do_sync,
    two_factor::two_factor_dialog,
    util::cursive_ext::{CursiveCallbackExt, CursiveExt},
};

const VIEW_NAME_PASSWORD: &str = "password";
const VIEW_NAME_EMAIL: &str = "email";

pub fn login_dialog(profile_name: &str, saved_email: impl Into<Option<String>>) -> Dialog {
    let password_field = EditView::new()
        .secret()
        .on_submit(|siv, _| submit_login(siv))
        .with_name(VIEW_NAME_PASSWORD)
        .fixed_width(40);

    let saved_email = saved_email.into();

    let email_field = match &saved_email {
        Some(em) => EditView::new().content(em),
        _ => EditView::new(),
    }
    .on_submit(|siv, _| {
        if siv.focus_name(VIEW_NAME_PASSWORD).is_err() {
            log::warn!("Focusing password field failed");
        }
    })
    .with_name(VIEW_NAME_EMAIL)
    .fixed_width(40);

    let mut layout = LinearLayout::vertical()
        .child(TextView::new("Email address"))
        .child(email_field)
        .child(TextView::new("Password"))
        .child(password_field);

    if saved_email.is_some() {
        let focus_res = layout.set_focus_index(3);
        if focus_res.is_err() {
            log::warn!("Focusing password field failed");
        }
    }

    Dialog::around(layout)
        .title(format!("Log in ({})", profile_name))
        .button("Submit", submit_login)
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

    let ud = c.get_user_data();
    let global_settings = ud.global_settings.clone();
    let profile_store = ud.profile_store.clone();

    tokio::spawn(async move {
        let client = ApiClient::new(&global_settings.server_url, &global_settings.device_id);
        let res = async {
            let (master_key, master_pw_hash, iterations) =
                do_prelogin(&client, &email, &password).await?;

            let store_pw_hash = master_pw_hash.clone();
            cb.send_msg(Box::new(move |c: &mut Cursive| {
                let mut ud = c.get_user_data();
                ud.master_key = Some(master_key);
                ud.master_password_hash = Some(store_pw_hash);
                ud.password_hash_iterations = Some(iterations);
            }));

            do_login(&client, &email, &master_pw_hash, None, &profile_store).await
        }
        .await;

        handle_login_response(res, cb, email);
    });
}

pub fn handle_login_response(res: Result<TokenResponse, anyhow::Error>, cb: CbSink, email: String) {
    match res {
        Result::Err(e) => {
            let err_msg = format!("Error: {:?}", e);
            cb.send_msg(Box::new(move |c: &mut Cursive| {
                c.get_user_data().clear_login_data();
                c.add_layer(
                    Dialog::text(err_msg)
                        .title("Login error")
                        .button("OK", move |siv| {
                            // Remove this dialog, and show the login dialog again
                            siv.pop_layer();
                            let d = login_dialog(
                                &siv.get_user_data().global_settings.profile,
                                Some(email.clone()),
                            );
                            siv.add_layer(d);
                        }),
                );
            }));
        }
        Result::Ok(token) => {
            match token {
                bitwarden::api::TokenResponse::Success(t) => {
                    cb.send_msg(Box::new(move |c: &mut Cursive| {
                        c.pop_layer();
                        let ud = c.get_user_data();
                        // Try to store the email
                        let store_res = ud
                            .profile_store
                            .edit(|d| d.saved_email = Some(email.clone()));
                        if let Err(e) = store_res {
                            log::error!("Failed to store profile data: {}", e);
                        }

                        ud.email = Some(Arc::new(email));
                        ud.token = Some(Arc::new(*t));

                        do_sync(c, true);
                    }))
                }
                bitwarden::api::TokenResponse::TwoFactorRequired(types) => {
                    cb.send_msg(Box::new(move |c: &mut Cursive| {
                        c.pop_layer();
                        let p = &c.get_user_data().global_settings.profile;
                        let dialog = two_factor_dialog(types, email, p); 
                        c.add_layer(dialog);
                    }));
                }
            }
        }
    }
}

async fn do_prelogin(
    client: &ApiClient,
    email: &str,
    password: &str,
) -> Result<(Arc<MasterKey>, Arc<MasterPasswordHash>, u32), anyhow::Error> {
    let iterations = client.prelogin(email).await?;
    let master_key = cipher::create_master_key(email, password, iterations);
    let master_pw_hash = cipher::create_master_password_hash(&master_key, password);
    Ok((Arc::new(master_key), Arc::new(master_pw_hash), iterations))
}

pub async fn do_login(
    client: &ApiClient,
    email: &str,
    master_pw_hash: &MasterPasswordHash,
    second_factor: Option<(TwoFactorProviderType, &str)>,
    profile_store: &ProfileStore,
) -> Result<TokenResponse, anyhow::Error> {
    let mut token_res = if let Some((two_factor_type, two_factor_token)) = second_factor {
        client
            .get_token(
                email,
                &master_pw_hash.base64_encoded(),
                Some((two_factor_type, two_factor_token, true)),
            )
            .await?
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

        client
            .get_token(email, &master_pw_hash.base64_encoded(), two_factor_param)
            .await?
    };

    if let bitwarden::api::TokenResponse::Success(t) = &mut token_res {
        if let Some(tft) = t.two_factor_token.take() {
            profile_store
                .edit(|d| d.saved_two_factor_token = Some(tft))
                .expect("Storing 2nd factor token failed");
        }
    }

    Ok(token_res)
}
