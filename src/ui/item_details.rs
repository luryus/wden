use std::time::Duration;

use super::data::UserData;
use crate::bitwarden::{
    api::{CipherData, CipherItem},
    cipher::{Cipher, EncryptionKey, MacKey},
};
use cursive::{Cursive, View, theme::{BaseColor, Color, Effect, Style}, traits::{Boxable, Nameable}, view::Margins, views::{Dialog, EditView, LayerPosition, LinearLayout, OnEventView, PaddedView, TextView}};
use lazy_static::lazy_static;

lazy_static! {
    static ref VALUE_STYLE: Style =
        Style::from(Effect::Reverse).combine(Color::Dark(BaseColor::Blue));
}

pub fn item_detail_dialog(ud: &mut UserData, item_id: &str) -> impl View {
    let (enc_key, mac_key) = ud.decrypt_keys().unwrap();

    // Find the item
    let item = ud
        .vault_data
        .as_ref()
        .and_then(|vd| vd.get(item_id))
        .expect("Item not found in vault data");

    let dialog_contents = match item.data {
        CipherData::Login(..) => login_dialog_contents(item, &enc_key, &mac_key),
        _ => LinearLayout::vertical(),
    };

    let mut key_hint_linear_layout = LinearLayout::vertical();

    if let CipherData::Login(_) = &item.data {
        key_hint_linear_layout
            .add_child(TextView::new("<p> Copy password").style(Color::Light(BaseColor::Black)));
        key_hint_linear_layout
            .add_child(TextView::new("<u> Copy username").style(Color::Light(BaseColor::Black)));
    }

    let dialog = Dialog::around(
        LinearLayout::vertical()
            .child(dialog_contents)
            .child(key_hint_linear_layout),
    )
    .button("Close", |s| {
        s.pop_layer();
    })
    .min_width(40);

    let mut ev = OnEventView::new(dialog);

    if let CipherData::Login(li) = &item.data {
        let password = li.password.decrypt_to_string(&enc_key, &mac_key);
        ev.set_on_event('p', move |siv| {
            super::clipboard::clip_exipiring_string(password.clone(), 30);
            show_copy_notification(siv, "Password copied");
        });

        let username = li.username.decrypt_to_string(&enc_key, &mac_key);
        ev.set_on_event('u', move |siv| {
            super::clipboard::clip_string(username.clone());
            show_copy_notification(siv, "Username copied");
        });
    }

    ev
}

fn show_copy_notification(cursive: &mut Cursive, message: &'static str) {
    // Not using Dialog::info here so that a named view can be added to the dialog
    // The named view is used later to find the dialog
    cursive.add_layer(Dialog::info(message).with_name("copy_notification"));

    let cb = cursive.cb_sink().clone();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        cb.send(Box::new(|siv| {
            let sc = siv.screen_mut();
            if let Some(LayerPosition::FromBack(l)) = sc.find_layer_from_name("copy_notification") {
                if l == sc.len() - 1 {
                    // If the dialog is the topmost layer, pop it
                    siv.pop_layer();
                }
            }
        })).expect("Sending message failed");
    });
}

fn login_dialog_contents(
    item: &CipherItem,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> LinearLayout {
    let login = match &item.data {
        CipherData::Login(l) => l,
        _ => unreachable!(),
    };
    LinearLayout::vertical()
        .child(TextView::new("Name"))
        .child(value_textview(&item.name, enc_key, mac_key))
        .child(TextView::new("Username"))
        .child(value_textview(&login.username, enc_key, mac_key))
        .child(TextView::new("Password"))
        .child(PaddedView::new(
            Margins::tb(0, 1),
            TextView::new("********").style(*VALUE_STYLE),
        ))
        .child(TextView::new("Uri"))
        .child(value_textview(&login.uri, enc_key, mac_key))
        .child(TextView::new("Notes"))
        .child(value_textview(&item.notes, enc_key, mac_key))
}

fn value_textview(
    cipher: &Cipher,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> PaddedView<TextView> {
    let tv = TextView::new(cipher.decrypt_to_string(enc_key, mac_key)).style(*VALUE_STYLE);
    PaddedView::new(Margins::tb(0, 1), tv)
}
