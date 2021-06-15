use cursive::{
    traits::{Boxable, Nameable},
    views::{Dialog, EditView, LinearLayout, Panel, TextView},
    Cursive,
};
use std::{convert::TryInto, error::Error};

use crate::bitwarden;

use super::{
    data::UserData,
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

    let server_url = c.user_data()
        .map(|ud: &mut UserData| ud.global_settings.server_url.clone())
        .unwrap();

    tokio::spawn(async move {
        let res = do_login(&server_url, &email, &password).await;

        match res {
            Result::Err(e) => {
                let err_msg = format!("Error: {:?}", e);
                cb.send(Box::new(move |c: &mut Cursive| {
                    c.add_layer(Dialog::text(err_msg).title("Login error").button(
                        "OK",
                        move |siv| {
                            // Remove this dialog, and show the login dialog again
                            siv.pop_layer();
                            siv.add_layer(login_dialog(&Some(email.clone())));
                        },
                    ));
                }))
                .expect("Sending the cursive callback message failed");
            }
            Result::Ok((key, pwhash, token)) => {
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
                        dat.master_key = Some(key);
                        dat.master_password_hash = Some(pwhash);
                        dat.token = Some(token);
                    });
                    do_sync(c);
                }))
                .expect("Sending the cursive callback message failed");
            }
        }
    });
}

async fn do_login(
    server_url: &str,
    email: &str,
    password: &str,
) -> Result<
    (
        bitwarden::cipher::MasterKey,
        bitwarden::cipher::MasterPasswordHash,
        bitwarden::api::TokenResponse,
    ),
    Box<dyn Error>,
> {
    let client = bitwarden::api::ApiClient::new(server_url);
    let iterations = client.prelogin(&email).await?;
    let master_key = bitwarden::cipher::create_master_key(
        &email.to_lowercase(),
        &password,
        (iterations as u32).try_into().unwrap(),
    );
    let master_pw_hash = bitwarden::cipher::create_master_password_hash(master_key, &password);
    let token = client
        .get_token(&email, &base64::encode(&master_pw_hash))
        .await?;

    Ok((master_key, master_pw_hash, token))
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
