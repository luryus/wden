use cursive::{views::Dialog, Cursive};
use simsearch::SimSearch;

use crate::{bitwarden::api::{ApiClient, CipherData}, ui::login::handle_login_response};

use super::{
    util::cursive_ext::{CursiveCallbackExt, CursiveExt},
    vault_table::show_vault, data::UserData,
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

    let server_url = user_data.global_settings.server_url.clone();
    let device_id = user_data.global_settings.device_id.clone();

    tokio::spawn(async move {
        if should_refresh {
            log::debug!("Refreshing access token");
            let client = ApiClient::new(&server_url, device_id.clone());

            let refresh_res = client.refresh_token(token).await;

            handle_login_response(refresh_res, ccb, email);
            return;
        }

        let client = ApiClient::with_token(&server_url, device_id, &token.access_token);
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

                    ud.simsearch = Some(create_search_index(&ud));

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

fn create_search_index(ud: &UserData) -> SimSearch<String> {
    let mut ss = SimSearch::new();
    if let Some(vd) = &ud.vault_data {
        if let Some(org_keys) = ud.get_org_keys_for_vault() {
            if let Some((enc_key, mac_key)) = ud.decrypt_keys() {
                for (k, v) in vd {
                    // Get appropriate keys for this item
                    let (ec, mc) = if let Some(oid) = &v.organization_id {
                        if let Some(keys) = org_keys.get(oid) {
                            (&keys.0, &keys.1)
                        } else {
                            continue;
                        }
                    } else {
                        (&enc_key, &mac_key)
                    };

                    // All items: name
                    let mut tokens = vec![
                        v.name.decrypt_to_string(ec, mc)
                    ];
                    // Login items: url and username
                    if let CipherData::Login(l) = &v.data {
                        tokens.push(l.username.decrypt_to_string(ec, mc));
                        tokens.push(l.uri.decrypt_to_string(ec, mc));      
                    };

                    // SimSearch will still tokenize (split) each of the token
                    // that are passed here. Passing them this way just avoids
                    // concatenating them into a string.
                    let tokens: Vec<_> = tokens.iter().map(|s| s.as_str()).collect();
                    ss.insert_tokens(k.clone(), &tokens);
                }
            }
        }
    }

    ss
}
