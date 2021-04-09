use std::{convert::TryInto, error::Error};
use cursive::{Cursive, traits::{Boxable, Nameable}, views::{Dialog, EditView, LinearLayout, Panel, TextView}};
use bitwarden_tui::{ui::data::UserData, bitwarden, ui::vault_table::vault_table_view};

#[tokio::main]
async fn main() {
    let mut siv = cursive::default();
    siv.set_user_data(UserData::default());

    siv.add_global_callback('§', Cursive::toggle_debug_console);
    cursive::logger::init();
    log::set_max_level(log::LevelFilter::Info);

    siv.add_layer(login_dialog());
    siv.run();
}

fn login_dialog() -> Dialog {
    let layout = LinearLayout::vertical()
        .child(TextView::new("Email address"))
        .child(EditView::new().with_name("email").fixed_width(40))
        .child(TextView::new("Password"))
        .child(
            EditView::new()
                .secret()
                .with_name("password")
                .fixed_width(40),
        );
    Dialog::around(layout)
        .title("Log in")
        .button("Submit", |c| handle_login(c))
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
    c.add_layer(Dialog::around(TextView::new("Signing in...")));

    let cb = c.cb_sink().clone();

    tokio::spawn(async move {
        let res = do_login(&email, &password).await;

        log::warn!("Foo");

        match res {
            Result::Err(e) => {
                let err_msg = format!("Error: {:?}", e);
                cb.send(Box::new(|c: &mut Cursive| {
                    c.add_layer(Dialog::around(TextView::new(err_msg)));
                }))
                .expect("Sending the cursive callback message failed");
            }
            Result::Ok((key, pwhash, token)) => {
                cb.send(Box::new(move |c: &mut Cursive| {
                    c.pop_layer();
                    c.with_user_data(|dat: &mut UserData| {
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
    let client = bitwarden::api::ApiClient::new();
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

fn do_sync(cursive: &mut Cursive) {

    cursive.add_layer(Dialog::around(TextView::new("Syncing...")));
    let ccb = cursive.cb_sink().clone();
    let user_data: &UserData = cursive.user_data().expect("User data not present");

    let access_token = user_data.token.as_ref()
        .map(|tr| tr.access_token.clone()).expect("Token not set");

    tokio::spawn(async move {
        let client = bitwarden::api::ApiClient::with_token(&access_token);
        let sync_res = client.sync().await;

        match sync_res {
            Ok(sync_res) => {
                ccb.send(Box::new(move |c: &mut Cursive| {
                    c.with_user_data(|ud: &mut UserData| {
                        ud.vault_data = Some(
                            sync_res.ciphers.into_iter()
                            .map(|ci| (ci.id.clone(), ci)).collect());
                    });
                    c.pop_layer();
                    show_item_list(c);
                })).expect("Sending cursive callback failed");
            },
            Err(sync_err) => {
                ccb.send(Box::new(move |c: &mut Cursive| {
                    let err_msg = format!("Error syncing: {}", sync_err);
                    c.add_layer(Dialog::around(TextView::new(err_msg)));
                })).expect("Sending cursive callback failed");
            }
        }
    });
}

fn show_item_list(c: &mut Cursive) {
    let ud: &mut UserData = c.user_data().unwrap();
    let (enc_key, mac_key) = bitwarden::cipher::decrypt_symmetric_keys(
        &ud.token.as_ref().unwrap().key, ud.master_key.unwrap()).unwrap();

    let table = vault_table_view(ud, &enc_key, &mac_key);
    let panel = Panel::new(table)
        .title("Vault")
        .full_screen();
    c.add_layer(panel);
}
