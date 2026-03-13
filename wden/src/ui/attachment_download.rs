use std::path::PathBuf;
use std::sync::Arc;

use cursive::{
    Cursive,
    view::Scrollable,
    views::{Dialog, SelectView},
};

use crate::bitwarden::{
    api::ApiClient,
    cipher::{EncMacKeys, decrypt_attachment_data},
};

use super::util::cursive_ext::CursiveExt;

pub fn start_attachment_download(siv: &mut Cursive, item_id: &str) {
    let ud = siv.get_user_data().with_unlocked_state().unwrap();
    let vault_data = Arc::clone(ud.vault_data());
    let Some(item) = vault_data.get(item_id) else {
        return;
    };

    if item.attachments.is_empty() {
        return;
    }

    let item_id = item_id.to_string();

    if item.attachments.len() == 1 {
        let attachment_id = item.attachments[0].id.clone();
        show_file_browser_for_attachment(siv, &item_id, &attachment_id);
    } else {
        show_attachment_selection(siv, &item_id);
    }
}

fn show_attachment_selection(siv: &mut Cursive, item_id: &str) {
    let ud = siv.get_user_data().with_unlocked_state().unwrap();
    let vault_data = Arc::clone(ud.vault_data());
    let item = &vault_data[item_id];

    let Some(keys) = ud.get_keys_for_item(item) else {
        log::warn!("Could not get keys for item");
        return;
    };

    let mut sel = SelectView::new();
    for attachment in &item.attachments {
        let name = attachment.file_name.decrypt_to_string(&keys);
        let label = match &attachment.size_name {
            Some(size) => format!("{name} ({size})"),
            None => name,
        };
        sel.add_item(label, attachment.id.clone());
    }

    let item_id = item_id.to_string();

    sel.set_on_submit(move |siv, attachment_id| {
        siv.pop_layer();
        show_file_browser_for_attachment(siv, &item_id, attachment_id);
    });

    let dialog = Dialog::around(sel.scrollable())
        .title("Select attachment")
        .dismiss_button("Cancel");

    siv.add_layer(dialog);
}

fn show_file_browser_for_attachment(siv: &mut Cursive, item_id: &str, attachment_id: &str) {
    let ud = siv.get_user_data().with_unlocked_state().unwrap();
    let vault_data = Arc::clone(ud.vault_data());
    let item = &vault_data[item_id];

    let Some(keys) = ud.get_keys_for_item(item) else {
        log::warn!("Could not get keys for item");
        return;
    };

    let attachment = item
        .attachments
        .iter()
        .find(|a| a.id == attachment_id)
        .unwrap();

    let default_filename = attachment.file_name.decrypt_to_string(&keys);
    let item_id = item_id.to_string();
    let attachment_id = attachment_id.to_string();

    let dialog = cursive_file_browser::save_file_dialog(
        "Save attachment",
        &default_filename,
        move |siv, path| {
            do_download(siv, &item_id, &attachment_id, path);
        },
    );

    siv.add_layer(dialog);
}

fn do_download(siv: &mut Cursive, item_id: &str, attachment_id: &str, save_path: PathBuf) {
    siv.add_layer(Dialog::text("Downloading..."));

    let ud = siv.get_user_data().with_unlocked_state().unwrap();
    let global_settings = ud.global_settings().clone();
    let access_token = ud.get_token_object().access_token.clone();

    let item_id = item_id.to_string();
    let attachment_id = attachment_id.to_string();
    let item_id_cb = item_id.clone();
    let attachment_id_cb = attachment_id.clone();

    siv.async_op(
        async move {
            let client = ApiClient::with_token(
                &global_settings.server_configuration,
                &global_settings.device_id,
                &access_token,
                global_settings.accept_invalid_certs,
            );

            client.download_attachment(&item_id, &attachment_id).await
        },
        move |siv, result| {
            siv.pop_layer(); // pop "Downloading..." dialog
            match result {
                Ok(encrypted_data) => {
                    decrypt_and_save(
                        siv,
                        &item_id_cb,
                        &attachment_id_cb,
                        &encrypted_data,
                        &save_path,
                    );
                }
                Err(e) => {
                    log::error!("Attachment download error: {e:?}");
                    siv.add_layer(
                        Dialog::text(format!("Error downloading attachment: {e}"))
                            .title("Error")
                            .dismiss_button("OK"),
                    );
                }
            }
        },
    );
}

fn decrypt_and_save(
    siv: &mut Cursive,
    item_id: &str,
    attachment_id: &str,
    encrypted_data: &[u8],
    save_path: &PathBuf,
) {
    let ud = siv.get_user_data().with_unlocked_state().unwrap();
    let vault_data = Arc::clone(ud.vault_data());
    let item = &vault_data[item_id];

    let Some(keys) = ud.get_keys_for_item(item) else {
        siv.add_layer(
            Dialog::text("Error: could not decrypt keys")
                .title("Error")
                .dismiss_button("OK"),
        );
        return;
    };

    let attachment = item
        .attachments
        .iter()
        .find(|a| a.id == attachment_id)
        .unwrap();

    // Decrypt attachment key if present, otherwise use item keys directly
    let decrypt_result = match &attachment.key {
        Some(key_cipher) => EncMacKeys::decrypt_from(key_cipher, &keys)
            .and_then(|attachment_keys| decrypt_attachment_data(encrypted_data, &attachment_keys)),
        None => decrypt_attachment_data(encrypted_data, &keys),
    };

    match decrypt_result {
        Ok(decrypted_data) => match std::fs::write(save_path, &decrypted_data) {
            Ok(()) => {
                siv.add_layer(
                    Dialog::text(format!("Saved to {}", save_path.display()))
                        .title("Download complete")
                        .dismiss_button("OK"),
                );
            }
            Err(e) => {
                log::error!("Error writing file: {e:?}");
                siv.add_layer(
                    Dialog::text(format!("Error saving file: {e}"))
                        .title("Error")
                        .dismiss_button("OK"),
                );
            }
        },
        Err(e) => {
            log::error!("Error decrypting attachment: {e:?}");
            siv.add_layer(
                Dialog::text(format!("Error decrypting attachment: {e}"))
                    .title("Error")
                    .dismiss_button("OK"),
            );
        }
    }
}
