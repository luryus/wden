use cursive::{Cursive, views::Dialog};

use crate::{bitwarden::api::ApiClient, ui::login::handle_login_response};

use super::{util::cursive_ext::{CursiveCallbackExt, CursiveExt}, vault_table::show_vault};


pub fn do_sync(cursive: &mut Cursive) {
    // Remove all layers first
    cursive.clear_layers();
    cursive.add_layer(Dialog::text("Syncing..."));
    let ccb = cursive.cb_sink().clone();
    let user_data = cursive.get_user_data();

    // Clear any data remaining
    user_data.vault_data = None;
    user_data.vault_table_rows = None;
    user_data.organizations = None;
    user_data.autolocker.lock().unwrap().clear_autolock_time();

    let email = user_data.email.clone()
        .expect("Email address was not set in UserData while syncing");

    let (access_token, should_refresh, refresh_token) = user_data
        .token
        .as_ref()
        .map(|tr| {
            (
                tr.access_token.clone(),
                tr.should_refresh(),
                tr.refresh_token.clone(),
            )
        })
        .expect("Token not set");

    let server_url = user_data.global_settings.server_url.clone();
    let device_id = user_data.global_settings.device_id.clone();

    tokio::spawn(async move {
        if should_refresh {
            log::debug!("Refreshing token");
            let client = ApiClient::new(&server_url, device_id.clone());
            let refresh_res = client.refresh_token(&refresh_token).await;

            handle_login_response(refresh_res, ccb, email);
            return;
        }

        let client = ApiClient::with_token(&server_url, device_id, &access_token);
        let sync_res = client.sync().await;

        match sync_res {
            Ok(sync_res) => {
                ccb.send_msg(Box::new(move |c: &mut Cursive| {
                    let ud = c.get_user_data();
                    ud.vault_data = Some(
                        sync_res
                            .ciphers
                            .into_iter()
                            .map(|ci| (ci.id.clone(), ci))
                            .collect(),
                    );
                    ud.organizations = Some(
                        sync_res
                            .profile
                            .organizations
                            .into_iter()
                            .map(|o| (o.id.clone(), o))
                            .collect(),
                    );
                    c.pop_layer();
                    show_vault(c);
                }));
            }
            Err(sync_err) => {
                ccb.send_msg(Box::new(move |c: &mut Cursive| {
                    let err_msg = format!("Error syncing: {}", sync_err);
                    c.add_layer(Dialog::text(err_msg));
                }));
            }
        }
    });
}