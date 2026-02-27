use std::sync::Arc;

use cursive::{
    Cursive,
    event::Callback,
    traits::Nameable,
    views::{Dialog, EditView, LinearLayout, PaddedView, SelectView, TextView},
};

use crate::bitwarden::api::{ApiClient, TwoFactorProviderType};

use super::{
    login::{do_login, handle_login_response, login_dialog},
    util::cursive_ext::CursiveExt,
};

const VIEW_NAME_AUTHENTICATOR_CODE: &str = "authenticator_code";

pub fn two_factor_dialog(
    mut types: Vec<TwoFactorProviderType>,
    email: Arc<String>,
    profile_name: &str,
) -> (Dialog, Callback) {
    // Only keep supported types
    types.retain(|x| {
        x == &TwoFactorProviderType::Authenticator || x == &TwoFactorProviderType::Email
    });

    if types.len() > 1 {
        let dialog = two_factor_type_selector_dialog(types, email.clone(), profile_name);
        return (dialog, Callback::dummy());
    }

    if types.contains(&TwoFactorProviderType::Authenticator) {
        let dialog = two_factor_dialog_authenticator(email, profile_name);
        (dialog, Callback::dummy())
    } else if types.contains(&TwoFactorProviderType::Email) {
        two_factor_dialog_email(email, profile_name)
    } else {
        let dialog = Dialog::text(
            "Account requires two-factor authentication, but active two-factor methods are not supported.",
        ).button("OK", move |siv| cancel_2fa(siv, Some(String::clone(&email))));
        (dialog, Callback::dummy())
    }
}

fn two_factor_type_selector_dialog(
    types: Vec<TwoFactorProviderType>,
    email: Arc<String>,
    profile_name: &str,
) -> Dialog {
    let email2 = email.clone();

    let select_view = SelectView::new()
        .with_all(types.into_iter().map(|t| (format!("{t:?}"), t)))
        .on_submit(move |siv, &t| {
            let ud = siv.get_user_data().with_logging_in_state().unwrap();
            let (dialog, cb) =
                two_factor_dialog(vec![t], email.clone(), &ud.global_settings().profile);

            siv.clear_layers();
            siv.add_layer(dialog);
            cb(siv);
        });

    Dialog::around(
        LinearLayout::vertical()
            .child(TextView::new("Choose 2FA method:"))
            .child(PaddedView::lrtb(0, 0, 1, 0, select_view)),
    )
    .title(format!("Two factor Login ({profile_name})"))
    .button("Cancel", move |siv| {
        cancel_2fa(siv, Some(String::clone(&email2)))
    })
}

fn two_factor_dialog_authenticator(email: Arc<String>, profile_name: &str) -> Dialog {
    let email2 = email.clone();
    let email3 = email.clone();

    Dialog::around(
        LinearLayout::vertical()
            .child(TextView::new("Enter authenticator code:"))
            .child(
                EditView::new()
                    .on_submit(move |siv, _| {
                        submit_two_factor(siv, TwoFactorProviderType::Authenticator, email.clone())
                    })
                    .with_name(VIEW_NAME_AUTHENTICATOR_CODE),
            ),
    )
    .title(format!("Two-factor Login ({profile_name})"))
    .button("Submit", move |siv| {
        submit_two_factor(siv, TwoFactorProviderType::Authenticator, email2.clone())
    })
    .button("Cancel", move |siv| {
        cancel_2fa(siv, Some(String::clone(&email3)))
    })
}

/// Clears layers and returns back to the login screen, with the specified email
/// pre-filled. Requires that the UI is in the logging in state, transitions to logged out state.
fn cancel_2fa(cursive: &mut Cursive, email: Option<String>) {
    let ud = cursive.get_user_data().with_logging_in_state().unwrap();
    let ud = ud.into_logged_out();
    let pn = &ud.global_settings().profile;
    let d = login_dialog(pn, email, false);

    cursive.clear_layers();
    cursive.add_layer(d);
}

fn two_factor_dialog_email(email: Arc<String>, profile_name: &str) -> (Dialog, Callback) {
    let title = format!("Two-factor Login ({profile_name})");

    let init_dialog = Dialog::text("Requesting verification code...");

    let cb = Callback::from_fn_once(move |siv: &mut Cursive| {
        let ud = siv.get_user_data().with_logging_in_state().unwrap();
        let global_settings = ud.global_settings().clone();
        let master_password_hash = ud.master_password_hash();

        let email2 = Arc::clone(&email);
        let email3 = Arc::clone(&email);
        let email4 = Arc::clone(&email);
        let email5 = Arc::clone(&email);
        let email6 = Arc::clone(&email);

        let actual_dialog = Dialog::around(
            LinearLayout::vertical()
                .child(TextView::new("Enter verification code sent to your email:"))
                .child(
                    EditView::new()
                        .on_submit(move |siv, _| {
                            submit_two_factor(siv, TwoFactorProviderType::Email, email2.clone())
                        })
                        .with_name(VIEW_NAME_AUTHENTICATOR_CODE),
                ),
        )
        .title(title.clone())
        .button("Submit", move |siv| {
            submit_two_factor(siv, TwoFactorProviderType::Email, email3.clone())
        })
        .button("Cancel", move |siv| {
            cancel_2fa(siv, Some(String::clone(&email4)))
        });

        siv.async_op(
            async move {
                let client = ApiClient::new(
                    &global_settings.server_configuration,
                    &global_settings.device_id,
                    global_settings.accept_invalid_certs,
                );

                client
                    .request_email_2fa_code(&email5, &master_password_hash.base64_encoded())
                    .await
            },
            move |siv, res| {
                siv.pop_layer();
                match res {
                    Ok(()) => siv.add_layer(actual_dialog),
                    Err(e) => siv.add_layer(
                        Dialog::text(format!("Failed to request verification code: {}", e))
                            .button("OK", move |siv| {
                                cancel_2fa(siv, Some(String::clone(&email6)))
                            }),
                    ),
                }
            },
        );
    });

    (init_dialog, cb)
}

fn submit_two_factor(c: &mut Cursive, two_factor_type: TwoFactorProviderType, email: Arc<String>) {
    let code = c
        .call_on_name(VIEW_NAME_AUTHENTICATOR_CODE, |view: &mut EditView| {
            view.get_content()
        })
        .expect("Reading authenticator code from field failed")
        .to_string();

    c.pop_layer();
    c.add_layer(Dialog::text("Signing in..."));

    let ud = c.get_user_data().with_logging_in_state().unwrap();

    let global_settings = ud.global_settings().clone();
    let profile_store = ud.profile_store();
    let master_pw_hash = ud.master_password_hash();
    let email2 = email.clone();

    c.async_op(
        async move {
            let client = ApiClient::new(
                &global_settings.server_configuration,
                &global_settings.device_id,
                global_settings.accept_invalid_certs,
            );
            do_login(
                &client,
                &email,
                master_pw_hash,
                Some((two_factor_type, &code)),
                None,
                &profile_store,
            )
            .await
        },
        move |siv, res| handle_login_response(siv, res, email2, false),
    );
}
