use std::sync::Arc;

use anyhow::Context;
use cursive::{
    Cursive, View,
    theme::Effect,
    traits::{Nameable, Resizable},
    view::{Margins, Selector},
    views::{Dialog, EditView, LinearLayout, PaddedView, TextView},
};
use cursive_secret_edit_view::SecretEditView;
use zeroize::Zeroizing;

use crate::{
    bitwarden::{
        self,
        api::{ApiClient, TokenResponse, TwoFactorProviderType},
        apikey::ApiKey,
        cipher::{self, MasterKey, MasterPasswordHash, PbkdfParameters},
    },
    profile::{GlobalSettings, ProfileStore},
};

use super::{sync::do_sync, two_factor::two_factor_dialog, util::cursive_ext::CursiveExt};

const VIEW_NAME_PASSWORD: &str = "password";
const VIEW_NAME_EMAIL: &str = "email";

pub fn login_dialog(
    profile_name: &str,
    saved_email: Option<String>,
    api_key_login: bool,
) -> Dialog {
    if api_key_login && saved_email.is_none() {
        panic!("Bug: email not present while trying to log in with api keys");
    }

    let submit_callback: Arc<dyn Fn(&mut Cursive) + Send + Sync> = if api_key_login {
        let saved_email = saved_email.clone().unwrap();
        Arc::new(move |siv: &mut Cursive| submit_api_key_login(siv, saved_email.clone()))
    } else {
        Arc::new(|siv: &mut Cursive| submit_login(siv))
    };
    let submit_callback2 = Arc::clone(&submit_callback);

    let password_field = SecretEditView::new()
        .on_submit(move |siv| submit_callback(siv))
        .with_name(VIEW_NAME_PASSWORD)
        .fixed_width(40);
    let should_focus_password = saved_email.is_some();

    let mut layout = if !api_key_login {
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

        LinearLayout::vertical()
            .child(TextView::new("Email address"))
            .child(email_field)
    } else {
        LinearLayout::vertical()
            .child(TextView::new("API key stored for email"))
            .child(PaddedView::new(
                Margins::tb(0, 1),
                TextView::new(saved_email.unwrap()).style(Effect::Bold),
            ))
    };

    layout = layout
        .child(TextView::new("Password"))
        .child(password_field);

    if should_focus_password {
        let focus_res = layout.focus_view(&Selector::Name(VIEW_NAME_PASSWORD));
        if focus_res.is_err() {
            log::warn!("Focusing password field failed");
        }
    }

    Dialog::around(layout)
        .title(format!("Log in ({profile_name})"))
        .button("Submit", move |siv| submit_callback2(siv))
}

fn submit_login(c: &mut Cursive) {
    let email = c
        .call_on_name(VIEW_NAME_EMAIL, |view: &mut EditView| view.get_content())
        .unwrap();
    let email = Arc::new(String::clone(&email));
    let email2 = email.clone();

    let password = c
        .call_on_name(VIEW_NAME_PASSWORD, |view: &mut SecretEditView| {
            // SecretEditView only gives the content out as a reference
            // to prevent (accidentally) leaking the data in memory.
            // Copy it to another zeroizing string.
            let content = view.get_content();
            let mut buf = Zeroizing::new(String::with_capacity(content.len() + 1));
            buf.push_str(content);
            buf
        })
        .unwrap();

    c.pop_layer();
    c.add_layer(Dialog::text("Signing in..."));

    let ud = c.get_user_data().with_logged_out_state().unwrap();
    let global_settings = ud.global_settings();
    let profile_store = ud.profile_store();

    c.async_op(
        async move {
            let client = ApiClient::new(
                &global_settings.server_configuration,
                &global_settings.device_id,
                global_settings.accept_invalid_certs,
            );
            async {
                let (master_key, master_pw_hash, pbkdf) =
                    do_prelogin(&client, &email, &password).await?;

                do_login(
                    &client,
                    &email,
                    master_pw_hash.clone(),
                    None,
                    &profile_store,
                )
                .await
                .map(|t| (t, master_key, master_pw_hash, email, pbkdf))
            }
            .await
        },
        move |siv, res| {
            match res {
                Ok((t, master_key, master_pw_hash, em, pbkdf)) => {
                    siv.get_user_data()
                        .with_logged_out_state()
                        .unwrap()
                        .into_logging_in(master_key, master_pw_hash, pbkdf, em.clone(), None);

                    handle_login_response(siv, Ok(t), em, false);
                }
                Err(e) => handle_login_response(siv, Err(e), email2, false),
            };
        },
    )
}

fn submit_api_key_login(c: &mut Cursive, email: String) {
    let email = Arc::new(email);
    let email2 = email.clone();

    let ud = c.get_user_data().with_logged_out_state().unwrap();
    let global_settings = ud.global_settings();

    let password = c
        .call_on_name(VIEW_NAME_PASSWORD, |view: &mut SecretEditView| {
            // SecretEditView only gives the content out as a reference
            // to prevent (accidentally) leaking the data in memory.
            // Copy it to another zeroizing string.
            let content = view.get_content();
            let mut buf = Zeroizing::new(String::with_capacity(content.len() + 1));
            buf.push_str(content);
            buf
        })
        .unwrap();

    c.pop_layer();
    c.add_layer(Dialog::text("Signing in..."));

    c.async_op(
        async move {
            let client = ApiClient::new(
                &global_settings.server_configuration,
                &global_settings.device_id,
                global_settings.accept_invalid_certs,
            );
            async {
                let api_key = do_api_key_prelogin(&email, &password, &global_settings).await?;
                do_login_with_api_key(&client, &email, &password, &api_key)
                    .await
                    .map(|(t, mk, kdf)| (t, mk, kdf, email, Arc::new(api_key)))
            }
            .await
        },
        move |siv, res| {
            match res {
                Ok((t, mk, kdf, em, ak)) => {
                    siv.get_user_data()
                        .with_logged_out_state()
                        .unwrap()
                        .into_logging_in(
                            mk,
                            Arc::new(MasterPasswordHash::default()),
                            kdf,
                            em.clone(),
                            Some(ak),
                        );

                    handle_login_response(siv, Ok(t), em, true);
                }
                Err(e) => handle_login_response(siv, Err(e), email2, true),
            };
        },
    )
}

pub fn handle_login_response(
    cursive: &mut Cursive,
    res: Result<TokenResponse, anyhow::Error>,
    email: Arc<String>,
    api_key_login: bool,
) {
    match res {
        Result::Err(e) => {
            let err_msg = format!("Error: {e:?}");
            // User data may be either in the LoggingIn or Refreshing state.
            // In both cases move to LoggedOut
            if let Some(ud) = cursive.get_user_data().with_logging_in_like_state() {
                ud.into_logged_out();
            }
            cursive.add_layer(Dialog::text(err_msg).title("Login error").button(
                "OK",
                move |siv| {
                    // Remove this dialog, and show the login dialog again
                    siv.pop_layer();
                    let d = login_dialog(
                        &siv.get_user_data()
                            .with_logged_out_state()
                            .unwrap()
                            .global_settings()
                            .profile,
                        Some(String::clone(&email)),
                        api_key_login,
                    );
                    siv.add_layer(d);
                },
            ));
        }
        Result::Ok(token) => {
            match token {
                bitwarden::api::TokenResponse::Success(t) => {
                    cursive.pop_layer();
                    let ud = cursive
                        .get_user_data()
                        .with_logging_in_like_state()
                        .unwrap();
                    // Try to store the email, unless this is an api key login. Those must already
                    // have the email stored, and the email is immutable
                    if !api_key_login {
                        let store_res = ud
                            .profile_store()
                            .edit(|d| d.saved_email = Some(String::clone(&email)));
                        if let Err(e) = store_res {
                            log::error!("Failed to store profile data: {e}");
                        }
                    }

                    ud.into_logged_in(Arc::new(*t));

                    do_sync(cursive, true);
                }
                bitwarden::api::TokenResponse::TwoFactorRequired(types) => {
                    cursive.pop_layer();
                    let p = &cursive
                        .get_user_data()
                        .with_logging_in_state()
                        .unwrap()
                        .global_settings()
                        .profile;
                    let dialog =
                        two_factor_dialog(types, email, p);
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
) -> Result<
    (
        Arc<MasterKey>,
        Arc<MasterPasswordHash>,
        Arc<PbkdfParameters>,
    ),
    anyhow::Error,
> {
    let pbkdf_params = client.prelogin(email).await?;
    let master_key = cipher::create_master_key(email, password, &pbkdf_params)?;
    let master_pw_hash = cipher::create_master_password_hash(&master_key, password);
    Ok((
        Arc::new(master_key),
        Arc::new(master_pw_hash),
        Arc::new(pbkdf_params),
    ))
}

async fn do_api_key_prelogin(
    email: &str,
    password: &str,
    global_settings: &GlobalSettings,
) -> Result<ApiKey, anyhow::Error> {
    let enc_api_key = global_settings
        .encrypted_api_key
        .as_ref()
        .context("Api key was not present in global settings")?;
    ApiKey::decrypt(enc_api_key, &global_settings.profile, email, password)
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
            .get_token(
                email,
                &master_pw_hash.base64_encoded(),
                two_factor_param,
            )
            .await?
    };

    if let bitwarden::api::TokenResponse::Success(t) = &mut token_res
        && let Some(tft) = t.two_factor_token.take()
    {
        profile_store
            .edit(|d| d.saved_two_factor_token = Some(tft))
            .expect("Storing 2nd factor token failed");
    }

    Ok(token_res)
}

pub async fn do_login_with_api_key(
    client: &ApiClient,
    email: &str,
    password: &str,
    api_key: &ApiKey,
) -> Result<(TokenResponse, Arc<MasterKey>, Arc<PbkdfParameters>), anyhow::Error> {
    let token_res = client.get_token_with_api_key(api_key).await?;

    let pbkdf_params = token_res
        .pbkdf_parameters()
        .context("Token did not contain pbkdf params")?;
    let master_key = cipher::create_master_key(email, password, &pbkdf_params)?;

    Ok((
        TokenResponse::Success(Box::new(token_res)),
        Arc::new(master_key),
        Arc::new(pbkdf_params),
    ))
}
