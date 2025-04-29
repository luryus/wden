use super::{
    data::{StatefulUserData, Unlocked},
    vault_table::show_copy_notification,
};
use crate::{
    bitwarden::{
        api::{CipherData, CipherItem},
        cipher::{Cipher, EncMacKeys},
    },
    ui::components::secret_text_view::SecretTextView,
};
use cursive::{
    View,
    theme::{BaseColor, Color, ColorStyle, Effect, Style},
    traits::{Nameable, Resizable},
    view::Margins,
    views::{Dialog, LinearLayout, OnEventView, PaddedView, ScrollView, TextView, ViewRef},
};
use lazy_static::lazy_static;
use log::warn;

lazy_static! {
    static ref VALUE_STYLE: Style = Style::from(Effect::Reverse).combine(ColorStyle::secondary());
}

pub fn item_detail_dialog(
    ud: &StatefulUserData<Unlocked>,
    item_id: &str,
) -> Option<impl View + use<>> {
    // Find the item
    let vault_data = ud.vault_data();
    let item = vault_data
        .get(item_id)
        .expect("Item not found in vault data");

    // Find keys that should be used for decrypting details
    let keys = ud.get_keys_for_item(item);
    if keys.is_none() {
        warn!("Error getting keys for item");
    }
    let keys = keys?;

    log::info!("Item: {:?}", &item);

    let dialog_contents = match item.data {
        CipherData::Login(..) => login_dialog_contents(item, &keys),
        CipherData::SecureNote(..) => note_dialog_contents(item, &keys),
        CipherData::Card(..) => card_dialog_contents(item, &keys),
        CipherData::Identity(..) => identity_dialog_contents(item, &keys),
        _ => LinearLayout::vertical(),
    };

    let mut key_hint_linear_layout = LinearLayout::vertical();

    if let CipherData::Login(_) = &item.data {
        key_hint_linear_layout
            .add_child(TextView::new("<p> Copy password").style(Color::Light(BaseColor::Black)));
        key_hint_linear_layout
            .add_child(TextView::new("<u> Copy username").style(Color::Light(BaseColor::Black)));
        key_hint_linear_layout.add_child(
            TextView::new("<s> Toggle password visibility").style(Color::Light(BaseColor::Black)),
        );
    }

    let dialog = Dialog::around(ScrollView::new(
        LinearLayout::vertical()
            .child(dialog_contents)
            .child(key_hint_linear_layout),
    ))
    .button("Close", |s| {
        s.pop_layer();
    })
    .min_width(40);

    let mut ev = OnEventView::new(dialog);

    if let CipherData::Login(li) = &item.data {
        let password = li.password.decrypt_to_string(&keys);
        ev.set_on_event('p', move |siv| {
            super::clipboard::clip_expiring_string(password.clone(), 30);
            show_copy_notification(siv, "Password copied");
        });

        let username = li.username.decrypt_to_string(&keys);
        ev.set_on_event('u', move |siv| {
            super::clipboard::clip_string(username.clone());
            show_copy_notification(siv, "Username copied");
        });

        ev.set_on_event('s', move |siv| {
            let mut pw_textview: ViewRef<PaddedView<SecretTextView>> =
                siv.find_name("password_textview").unwrap();
            pw_textview.get_inner_mut().toggle_hidden();
        });
    }

    Some(ev)
}

fn login_dialog_contents(item: &CipherItem, keys: &EncMacKeys) -> LinearLayout {
    let login = match &item.data {
        CipherData::Login(l) => l,
        _ => unreachable!(),
    };
    let mut ll = LinearLayout::vertical();
    add_label_value_text(&mut ll, "Name", &item.name, keys);
    add_label_value_text(&mut ll, "Username", &login.username, keys);
    ll.add_child(TextView::new("Password"));
    ll.add_child(value_secret_textview(&login.password, keys).with_name("password_textview"));
    add_label_value_text(&mut ll, "Uri", &login.uri, keys);
    add_label_value_text(&mut ll, "Notes", &item.notes, keys);

    ll
}

fn note_dialog_contents(item: &CipherItem, keys: &EncMacKeys) -> LinearLayout {
    let mut ll = LinearLayout::vertical();
    add_label_value_text(&mut ll, "Name", &item.name, keys);
    add_label_value_text(&mut ll, "Notes", &item.notes, keys);
    ll
}

fn card_dialog_contents(item: &CipherItem, keys: &EncMacKeys) -> LinearLayout {
    let card = match &item.data {
        CipherData::Card(c) => c,
        _ => unreachable!(),
    };

    let exp_month = card.exp_month.decrypt_to_string(keys);
    let exp_year = card.exp_year.decrypt_to_string(keys);
    let expiry = format!("{exp_month} / {exp_year}");

    let mut ll = LinearLayout::vertical();
    add_label_value_text(&mut ll, "Name", &item.name, keys);
    add_label_value_text(&mut ll, "Brand", &card.brand, keys);
    add_label_value_text(&mut ll, "Number", &card.number, keys);
    add_label_value_text(&mut ll, "Code", &card.code, keys);
    ll.add_child(TextView::new("Expires"));
    ll.add_child(PaddedView::new(
        Margins::tb(0, 1),
        TextView::new(expiry).style(*VALUE_STYLE),
    ));
    add_label_value_text(&mut ll, "Card holder", &card.cardholder_name, keys);
    add_label_value_text(&mut ll, "Notes", &item.notes, keys);
    ll
}

fn identity_dialog_contents(item: &CipherItem, keys: &EncMacKeys) -> LinearLayout {
    let identity = match &item.data {
        CipherData::Identity(id) => id,
        _ => unreachable!(),
    };

    let mut ll = LinearLayout::vertical();

    add_label_value_text(&mut ll, "Name", &item.name, keys);

    add_label_value_text(&mut ll, "Title", &identity.title, keys);
    add_label_value_text(&mut ll, "First name", &identity.first_name, keys);
    add_label_value_text(&mut ll, "Middle name", &identity.middle_name, keys);
    add_label_value_text(&mut ll, "Last name", &identity.last_name, keys);

    add_label_value_text(&mut ll, "Phone", &identity.phone, keys);
    add_label_value_text(&mut ll, "Email", &identity.email, keys);

    add_label_value_text(&mut ll, "Address 1", &identity.address_1, keys);
    add_label_value_text(&mut ll, "Address 2", &identity.address_2, keys);
    add_label_value_text(&mut ll, "Address 3", &identity.address_3, keys);
    add_label_value_text(&mut ll, "Postal code", &identity.postal_code, keys);
    add_label_value_text(&mut ll, "City", &identity.city, keys);
    add_label_value_text(&mut ll, "State", &identity.state, keys);
    add_label_value_text(&mut ll, "Country", &identity.country, keys);

    add_label_value_text(&mut ll, "Company", &identity.company, keys);
    add_label_value_text(&mut ll, "SSN", &identity.ssn, keys);
    add_label_value_text(&mut ll, "License number", &identity.license_number, keys);
    add_label_value_text(&mut ll, "Passport number", &identity.passport_number, keys);
    add_label_value_text(&mut ll, "Username", &identity.username, keys);

    add_label_value_text(&mut ll, "Notes", &item.notes, keys);

    ll
}

fn add_label_value_text(ll: &mut LinearLayout, name: &str, value: &Cipher, keys: &EncMacKeys) {
    ll.add_child(TextView::new(name));
    ll.add_child(value_textview(value, keys));
}

fn value_textview(cipher: &Cipher, keys: &EncMacKeys) -> PaddedView<TextView> {
    let tv = TextView::new(cipher.decrypt_to_string(keys)).style(*VALUE_STYLE);
    PaddedView::new(Margins::tb(0, 1), tv)
}

fn value_secret_textview(cipher: &Cipher, keys: &EncMacKeys) -> PaddedView<SecretTextView> {
    let tv = SecretTextView::new(cipher.decrypt_to_string(keys)).style(*VALUE_STYLE);
    PaddedView::new(Margins::tb(0, 1), tv)
}
