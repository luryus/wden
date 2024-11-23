use std::sync::Arc;

use cursive::{views::Dialog, Cursive};

use crate::{bitwarden::api::ApiClient, ui::login};

use super::{util::cursive_ext::CursiveExt, vault_table::show_vault};

pub fn do_sync(cursive: &mut Cursive, just_refreshed_token: bool) {
    // Remove all layers first
    cursive.clear_layers();
    cursive.add_layer(Dialog::text("Syncing..."));
    log::info!("Running sync.");
    let user_data = cursive.get_user_data();

    // Clear any data remaining
    let user_data = if let Some(unlocked_user_data) = user_data.with_unlocked_state() {
        unlocked_user_data.into_logged_in()
    } else {
        user_data.with_logged_in_state().unwrap()
    };

    let global_settings = user_data.global_settings();
    let email = user_data.email();
    let token = user_data.token();
    let api_key = user_data.api_key();

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

    if !just_refreshed_token && (should_refresh || global_settings.always_refresh_token_on_sync) {
        let _ = user_data.into_refreshing();
        let is_api_key_login = api_key.is_some();
        cursive.async_op(
            async move {
                log::info!("Refreshing access token");
                let client = ApiClient::new(
                    &global_settings.server_configuration,
                    &global_settings.device_id,
                    global_settings.accept_invalid_certs,
                );

                client.refresh_token(&token, api_key.as_deref()).await
            },
            move |siv, refresh_res| {
                login::handle_login_response(siv, refresh_res, email, false, is_api_key_login);
            },
        );
        // Login response handling above calls do_sync again, so nothing to do here
        return;
    }

    // Do sync, no need to worry about refreshing
    cursive.async_op(
        async move {
            let client = ApiClient::with_token(
                &global_settings.server_configuration,
                &global_settings.device_id,
                &token.access_token,
                global_settings.accept_invalid_certs,
            );

            client.sync().await
        },
        |c, sync_res| match sync_res {
            Ok(sync_res) => {
                let ud = c.get_user_data().with_logged_in_state().unwrap();
                let vault_data = Arc::new(
                    sync_res
                        .ciphers
                        .into_iter()
                        .map(|ci| (ci.id.clone(), ci))
                        .collect(),
                );
                let organizations = Arc::new(
                    sync_res
                        .profile
                        .organizations
                        .into_iter()
                        .map(|o| (o.id.clone(), o))
                        .collect(),
                );
                let collections = Arc::new(
                    sync_res
                        .collections
                        .into_iter()
                        .map(|c| (c.id.clone(), c))
                        .collect(),
                );

                ud.into_unlocked(vault_data, organizations, collections);

                c.pop_layer();
                show_vault(c);
            }
            Err(sync_err) => {
                let err_msg = format!("Error syncing: {sync_err}");
                c.add_layer(Dialog::text(err_msg));
            }
        },
    );
}
