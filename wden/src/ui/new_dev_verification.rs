use std::sync::Arc;

use cursive::{
    Cursive,
    traits::Nameable,
    views::{Dialog, EditView, LinearLayout, TextView},
};

use crate::bitwarden::api::ApiClient;

use super::{
    login::{do_login, handle_login_response, login_dialog},
    util::cursive_ext::CursiveExt,
};

const VIEW_NAME_NEW_DEV_OTP: &str = "new_dev_otp";

pub fn new_device_verify_dialog(email: Arc<String>, profile_name: &str) -> Dialog {
    let email2 = email.clone();
    let email3 = email.clone();

    Dialog::around(
        LinearLayout::vertical()
            .child(TextView::new("New device verification required."))
            .child(TextView::new(
                "Enter the verification code sent to your email:",
            ))
            .child(
                EditView::new()
                    .on_submit(move |siv, _| submit_dev_verification(siv, email.clone()))
                    .with_name(VIEW_NAME_NEW_DEV_OTP),
            ),
    )
    .title(format!("Device Verification ({profile_name})"))
    .button("Submit", move |siv| {
        submit_dev_verification(siv, email2.clone())
    })
    .button("Cancel", move |siv| {
        let ud = siv.get_user_data().with_logging_in_state().unwrap();
        let ud = ud.into_logged_out();
        let pn = &ud.global_settings().profile;
        let d = login_dialog(pn, Some(email3.to_string()), false);
        siv.clear_layers();
        siv.add_layer(d);
    })
}

fn submit_dev_verification(c: &mut Cursive, email: Arc<String>) {
    let code = c
        .call_on_name(VIEW_NAME_NEW_DEV_OTP, |view: &mut EditView| {
            view.get_content()
        })
        .expect("Reading verification code from field failed")
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
                None,
                Some(&code),
                &profile_store,
            )
            .await
        },
        move |siv, res| handle_login_response(siv, res, email2, false),
    );
}
