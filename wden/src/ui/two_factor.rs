use std::sync::Arc;

use cursive::{
    Cursive,
    traits::Nameable,
    views::{Dialog, EditView, LinearLayout, TextView},
};

use crate::bitwarden::api::{ApiClient, TwoFactorProviderType};

use super::{
    login::{do_login, handle_login_response, login_dialog},
    util::cursive_ext::CursiveExt,
};

const VIEW_NAME_AUTHENTICATOR_CODE: &str = "authenticator_code";

pub fn two_factor_dialog(
    types: Vec<TwoFactorProviderType>,
    email: Arc<String>,
    profile_name: &str,
) -> Dialog {
    if !types.contains(&TwoFactorProviderType::Authenticator) {
        Dialog::info(
            "Account requires two-factor authentication, but active two-factor methods are not supported.",
        )
    } else {
        let email2 = email.clone();
        let email3 = email.clone();

        Dialog::around(
            LinearLayout::vertical()
                .child(TextView::new("Enter authenticator code:"))
                .child(
                    EditView::new()
                        .on_submit(move |siv, _| submit_two_factor(siv, email.clone()))
                        .with_name(VIEW_NAME_AUTHENTICATOR_CODE),
                ),
        )
        .title(format!("Two-factor Login ({profile_name})"))
        .button("Submit", move |siv| submit_two_factor(siv, email2.clone()))
        .button("Cancel", move |siv| {
            let ud = siv.get_user_data().with_logging_in_state().unwrap();
            let ud = ud.into_logged_out();
            let pn = &ud.global_settings().profile;
            let d = login_dialog(pn, Some(email3.to_string()), false);
            siv.clear_layers();
            siv.add_layer(d);
        })
    }
}

fn submit_two_factor(c: &mut Cursive, email: Arc<String>) {
    let code = c
        .call_on_name(VIEW_NAME_AUTHENTICATOR_CODE, |view: &mut EditView| {
            view.get_content()
        })
        .expect("Reading authenticator code from field failed")
        .to_string();

    c.pop_layer();
    c.add_layer(Dialog::text("Signing in..."));

    let ud = c.get_user_data().with_logging_in_state().unwrap();

    let global_settings = ud.global_settings();
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
                Some((TwoFactorProviderType::Authenticator, &code)),
                None,
                &profile_store,
            )
            .await
        },
        move |siv, res| handle_login_response(siv, res, email2, false),
    );
}
