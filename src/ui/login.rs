use std::sync::Arc;

use cursive::{
    traits::{Nameable, Resizable},
    views::{Dialog, EditView, LinearLayout, TextView},
    Cursive,
};

use crate::{
    bitwarden::{
        self,
        api::{ApiClient, TokenResponse, TwoFactorProviderType},
        cipher::{self, MasterKey, MasterPasswordHash},
    },
    profile::ProfileStore,
};

use super::{sync::do_sync, two_factor::two_factor_dialog, util::cursive_ext::CursiveExt};

const VIEW_NAME_PASSWORD: &str = "password";
const VIEW_NAME_EMAIL: &str = "email";

pub fn login_dialog(profile_name: &str, saved_email: Option<String>) -> Dialog {
    let password_field = EditView::new()
        .secret()
        .on_submit(|siv, _| submit_login(siv))
        .with_name(VIEW_NAME_PASSWORD)
        .fixed_width(40);

    let should_focus_password = saved_email.is_some();
    let email_field = match saved_email {
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

    if should_focus_password {
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
        .unwrap();
    let email = Arc::new(String::clone(&email));
    let email2 = email.clone();

    let password = c
        .call_on_name("password", |view: &mut EditView| view.get_content())
        .unwrap()
        .to_string();

    c.pop_layer();
    c.add_layer(Dialog::text("Signing in..."));

    let ud = c.get_user_data();
    let global_settings = ud.global_settings();
    let profile_store = ud.profile_store();

    c.async_op(
        async move {
            let client = ApiClient::new(&global_settings.server_url, &global_settings.device_id);
            async {
                let (master_key, master_pw_hash, iterations) =
                    do_prelogin(&client, &email, &password).await?;

                do_login(
                    &client,
                    &email,
                    master_pw_hash.clone(),
                    None,
                    &profile_store,
                )
                .await
                .map(|t| (t, master_key, master_pw_hash, email, iterations))
            }
            .await
        },
        |siv, res| {
            match res {
                Ok((t, master_key, master_pw_hash, em, iterations)) => {
                    siv.get_user_data()
                        .with_logged_out_state()
                        .unwrap()
                        .into_logging_in(master_key, master_pw_hash, iterations, em.clone());

                    handle_login_response(siv, Ok(t), em);
                }
                Err(e) => handle_login_response(siv, Err(e), email2),
            };
        },
    )
}

pub fn handle_login_response(
    cursive: &mut Cursive,
    res: Result<TokenResponse, anyhow::Error>,
    email: Arc<String>,
) {
    match res {
        Result::Err(e) => {
            let err_msg = format!("Error: {:?}", e);
            cursive
                .get_user_data()
                .with_logging_in_state()
                .unwrap()
                .into_logged_out();
            cursive.add_layer(Dialog::text(err_msg).title("Login error").button(
                "OK",
                move |siv| {
                    // Remove this dialog, and show the login dialog again
                    siv.pop_layer();
                    let d = login_dialog(
                        &siv.get_user_data().global_settings().profile,
                        Some(String::clone(&email)),
                    );
                    siv.add_layer(d);
                },
            ));
        }
        Result::Ok(token) => {
            match token {
                bitwarden::api::TokenResponse::Success(t) => {
                    cursive.pop_layer();
                    let ud = cursive.get_user_data();
                    // Try to store the email
                    let store_res = ud
                        .profile_store()
                        .edit(|d| d.saved_email = Some(String::clone(&email)));
                    if let Err(e) = store_res {
                        log::error!("Failed to store profile data: {}", e);
                    }

                    ud.with_logging_in_state()
                        .unwrap()
                        .into_logged_in(Arc::new(*t));

                    do_sync(cursive, true);
                }
                bitwarden::api::TokenResponse::TwoFactorRequired(types) => {
                    cursive.pop_layer();
                    let p = &cursive.get_user_data().global_settings().profile;
                    let dialog = two_factor_dialog(types, email, p);
                    cursive.add_layer(dialog);
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
    master_pw_hash: Arc<MasterPasswordHash>,
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
