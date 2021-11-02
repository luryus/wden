use cursive::{Cursive, traits::Nameable, views::{Dialog, EditView, LinearLayout, TextView}};

use crate::bitwarden::api::TwoFactorProviderType;

use super::{login::{do_login, handle_login_response}, util::cursive_ext::CursiveExt};


const VIEW_NAME_AUTHENTICATOR_CODE: &str = "authenticator_code";

pub fn two_factor_dialog(types: Vec<TwoFactorProviderType>, email: String) -> Dialog {
    if !types.contains(&TwoFactorProviderType::Authenticator) {
        Dialog::info("Account requires two-factor authentication, but active two-factor methods are not supported.")
    } else {
        // Clone email because it's needed in two closures
        let email2 = email.clone();
        Dialog::around(
            LinearLayout::vertical()
                .child(TextView::new("Enter authenticator code:"))
                .child(
                    EditView::new()
                        .on_submit(move |siv, _| submit_two_factor(siv, email2.clone()))
                        .with_name(VIEW_NAME_AUTHENTICATOR_CODE),
                ),
        )
        .button("Submit", move |siv| submit_two_factor(siv, email.clone()))
        .dismiss_button("Cancel")
    }
}


fn submit_two_factor(c: &mut Cursive, email: String) {
    let code = c
        .call_on_name(VIEW_NAME_AUTHENTICATOR_CODE, |view: &mut EditView| view.get_content())
        .expect("Reading authenticator code from field failed")
        .to_string();

    c.pop_layer();
    c.add_layer(Dialog::text("Signing in..."));

    let cb = c.cb_sink().clone();

    let ud = c.get_user_data();

    let server_url = ud.global_settings.server_url.clone();
    let device_id = ud.global_settings.device_id.clone();
    let profile_store = ud.profile_store.clone();

    // Have to clone the hash here, because it's not
    // really possible to access user_data inside the async
    // block in any good form
    let master_pw_hash = ud.master_password_hash.clone()
        .expect("Password hash was not set while submitting 2FA");

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