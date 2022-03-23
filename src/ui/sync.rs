use std::sync::Arc;

use cursive::{views::Dialog, Cursive};

use crate::{
    bitwarden::api::ApiClient,
    ui::{login, search},
};

use super::{
    util::cursive_ext::{CursiveCallbackExt, CursiveExt},
    vault_table::show_vault,
};

pub fn do_sync(cursive: &mut Cursive, just_refreshed_token: bool) {
    // Remove all layers first
    cursive.clear_layers();
    cursive.add_layer(Dialog::text("Syncing..."));
    log::info!("Running sync.");
    let ccb = cursive.cb_sink().clone();
    let user_data = cursive.get_user_data();

    // Clear any data remaining
    user_data.vault_data = None;
    user_data.vault_table_rows = None;
    user_data.organizations = None;
    user_data.autolocker.lock().unwrap().clear_autolock_time();

    let email = user_data
        .email
        .clone()
        .expect("Email address was not set in UserData while syncing");

    let token = user_data.token.clone().expect("Token not set");

    let should_refresh = token.should_refresh();
    if should_refresh && just_refreshed_token {
        // Error: we're in a refresh loop, abort
        let alert = Dialog::text("Error: token refresh loop detected. The program will now exit.")
            .title("Access token refresh error")
            .button("OK", |siv| siv.quit());
        cursive.clear_layers();
        cursive.add_layer(alert);
        return;
    }

    let global_settings = user_data.global_settings.clone();

    tokio::spawn(async move {
        if should_refresh {
            log::debug!("Refreshing access token");
            let client = ApiClient::new(&global_settings.server_url, &global_settings.device_id);
            let refresh_res = client.refresh_token(&token).await;
            login::handle_login_response(refresh_res, ccb, email.to_string());
            return;
        }

        let client = ApiClient::with_token(
            &global_settings.server_url,
            &global_settings.device_id,
            &token.access_token,
        );
        let sync_res = client.sync().await;

        match sync_res {
            Ok(sync_res) => {
                ccb.send_msg(Box::new(move |c: &mut Cursive| {
                    let ud = c.get_user_data();
                    ud.vault_data = Some(Arc::new(
                        sync_res
                            .ciphers
                            .into_iter()
                            .map(|ci| (ci.id.clone(), ci))
                            .collect(),
                    ));
                    ud.organizations = Some(Arc::new(
                        sync_res
                            .profile
                            .organizations
                            .into_iter()
                            .map(|o| (o.id.clone(), o))
                            .collect(),
                    ));

                    search::update_search_index(ud);

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
