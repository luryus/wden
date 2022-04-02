use std::sync::Arc;

use cursive::{
    traits::Nameable,
    views::{Dialog, EditView, LinearLayout, TextView},
    Cursive,
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
        Dialog::info("Account requires two-factor authentication, but active two-factor methods are not supported.")
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
        .title(format!("Two-factor Login ({})", profile_name))
        .button("Submit", move |siv| submit_two_factor(siv, email2.clone()))
        .button("Cancel", move |siv| {
            let pn = &siv.get_user_data().global_settings.profile;
            let d = login_dialog(pn, Some(email3.to_string()));
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

    let ud = c.get_user_data();

    let global_settings = ud.global_settings.clone();
    let profile_store = ud.profile_store.clone();
    let master_pw_hash = ud
        .master_password_hash
        .clone()
        .expect("Password hash was not set while submitting 2FA");
    let email2 = email.clone();

    c.async_op(
        async move {
            let client = ApiClient::new(&global_settings.server_url, &global_settings.device_id);
            do_login(
                &client,
                &email,
                master_pw_hash,
                Some((TwoFactorProviderType::Authenticator, &code)),
                &profile_store
            )
            .await
        },
        move |siv, res| handle_login_response(siv, res, email2),
    );
}
