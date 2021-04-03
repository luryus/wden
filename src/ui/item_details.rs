use super::data::UserData;
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

    let dialog = Dialog::around(dialog_contents)
        .button("Close", |s| {
            s.pop_layer();
        })
        .min_width(40);

    let mut ev = OnEventView::new(dialog);

    if let CipherData::Login(li) = &item.data {
        let password = li.password.decrypt_to_string(&enc_key, &mac_key);
        ev.set_on_event('p', move |_| {
            super::clipboard::clip_exipiring_string(password.clone(), 30);
        });
        let username = li.username.decrypt_to_string(&enc_key, &mac_key);
        ev.set_on_event('u', move |_| {
            super::clipboard::clip_string(username.clone());
        });
    }

    ev
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
        .child(value_textview(&login.password, enc_key, mac_key))
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
