use super::{data::UserData, vault_table::show_copy_notification};
use crate::bitwarden::{
    api::{CipherData, CipherItem},
    cipher::{Cipher, EncryptionKey, MacKey},
};
use cursive::{
    theme::{BaseColor, Color, Effect, Style},
    traits::Boxable,
    view::Margins,
    views::{Dialog, LinearLayout, OnEventView, PaddedView, TextView},
    View,
};
use lazy_static::lazy_static;
use log::warn;

lazy_static! {
    static ref VALUE_STYLE: Style =
        Style::from(Effect::Reverse).combine(Color::Dark(BaseColor::Blue));
}

pub fn item_detail_dialog(ud: &mut UserData, item_id: &str) -> Option<impl View> {
    // Find the item
    let item = ud
        .vault_data
        .as_ref()
        .and_then(|vd| vd.get(item_id))
        .expect("Item not found in vault data");

    // Find keys that should be used for decrypting details
    let keys = ud.get_keys_for_item(&item);
    if keys.is_none() {
        warn!("Error getting keys for item");
    }
    let (enc_key, mac_key) = keys?;

    let dialog_contents = match item.data {
        CipherData::Login(..) => login_dialog_contents(item, &enc_key, &mac_key),
        CipherData::SecureNote => note_dialog_contents(item, &enc_key, &mac_key),
        CipherData::Card(..) => card_dialog_contents(item, &enc_key, &mac_key),
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

    Some(ev)
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

fn note_dialog_contents(
    item: &CipherItem,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> LinearLayout {
    LinearLayout::vertical()
        .child(TextView::new("Name"))
        .child(value_textview(&item.name, enc_key, mac_key))
        .child(TextView::new("Notes"))
        .child(value_textview(&item.notes, enc_key, mac_key))
}

fn card_dialog_contents(
    item: &CipherItem,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> LinearLayout {
    let card = match &item.data {
        CipherData::Card(c) => c,
        _ => unreachable!(),
    };

    let exp_month = card.exp_month.decrypt_to_string(enc_key, mac_key);
    let exp_year = card.exp_year.decrypt_to_string(enc_key, mac_key);
    let expiry = format!("{} / {}", exp_month, exp_year);

    LinearLayout::vertical()
        .child(TextView::new("Name"))
        .child(value_textview(&item.name, enc_key, mac_key))
        .child(TextView::new("Brand"))
        .child(value_textview(&card.brand, enc_key, mac_key))
        .child(TextView::new("Number"))
        .child(value_textview(&card.number, enc_key, mac_key))
        .child(TextView::new("Code"))
        .child(value_textview(&card.code, enc_key, mac_key))
        .child(TextView::new("Expires"))
        .child(PaddedView::new(
            Margins::tb(0, 1),
            TextView::new(expiry).style(*VALUE_STYLE),
        ))
        .child(TextView::new("Card holder"))
        .child(value_textview(&card.card_holder_name, enc_key, mac_key))
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
