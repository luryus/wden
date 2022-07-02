use super::{
    data::{StatefulUserData, Unlocked},
    vault_table::show_copy_notification,
};
use crate::{
    bitwarden::{
        api::{CipherData, CipherItem},
        cipher::{Cipher, EncryptionKey, MacKey},
    },
    ui::components::secret_text_view::SecretTextView,
};
use cursive::{
    theme::{BaseColor, Color, ColorStyle, Effect, Style},
    traits::{Nameable, Resizable},
    view::Margins,
    views::{Dialog, LinearLayout, OnEventView, PaddedView, ScrollView, TextView, ViewRef},
    View,
};
use lazy_static::lazy_static;
use log::warn;

lazy_static! {
    static ref VALUE_STYLE: Style = Style::from(Effect::Reverse).combine(ColorStyle::secondary());
}

pub fn item_detail_dialog(ud: &StatefulUserData<Unlocked>, item_id: &str) -> Option<impl View> {
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
    let (enc_key, mac_key) = keys?;

    let dialog_contents = match item.data {
        CipherData::Login(..) => login_dialog_contents(item, &enc_key, &mac_key),
        CipherData::SecureNote => note_dialog_contents(item, &enc_key, &mac_key),
        CipherData::Card(..) => card_dialog_contents(item, &enc_key, &mac_key),
        CipherData::Identity(..) => identity_dialog_contents(item, &enc_key, &mac_key),
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
        let password = li.password.decrypt_to_string(&enc_key, &mac_key);
        ev.set_on_event('p', move |siv| {
            super::clipboard::clip_expiring_string(password.clone(), 30);
            show_copy_notification(siv, "Password copied");
        });

        let username = li.username.decrypt_to_string(&enc_key, &mac_key);
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

fn login_dialog_contents(
    item: &CipherItem,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> LinearLayout {
    let login = match &item.data {
        CipherData::Login(l) => l,
        _ => unreachable!(),
    };
    let mut ll = LinearLayout::vertical();
    add_label_value_text(&mut ll, "Name", &item.name, enc_key, mac_key);
    add_label_value_text(&mut ll, "Username", &login.username, enc_key, mac_key);
    ll.add_child(TextView::new("Password"));
    ll.add_child(
        value_secret_textview(&login.password, enc_key, mac_key).with_name("password_textview"),
    );
    add_label_value_text(&mut ll, "Uri", &login.uri, enc_key, mac_key);
    add_label_value_text(&mut ll, "Notes", &item.notes, enc_key, mac_key);

    ll
}

fn note_dialog_contents(
    item: &CipherItem,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> LinearLayout {
    let mut ll = LinearLayout::vertical();
    add_label_value_text(&mut ll, "Name", &item.name, enc_key, mac_key);
    add_label_value_text(&mut ll, "Notes", &item.notes, enc_key, mac_key);
    ll
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

    let mut ll = LinearLayout::vertical();
    add_label_value_text(&mut ll, "Name", &item.name, enc_key, mac_key);
    add_label_value_text(&mut ll, "Brand", &card.brand, enc_key, mac_key);
    add_label_value_text(&mut ll, "Number", &card.number, enc_key, mac_key);
    add_label_value_text(&mut ll, "Code", &card.code, enc_key, mac_key);
    ll.add_child(TextView::new("Expires"));
    ll.add_child(PaddedView::new(
        Margins::tb(0, 1),
        TextView::new(expiry).style(*VALUE_STYLE),
    ));
    add_label_value_text(
        &mut ll,
        "Card holder",
        &card.cardholder_name,
        enc_key,
        mac_key,
    );
    add_label_value_text(&mut ll, "Notes", &item.notes, enc_key, mac_key);
    ll
}

fn identity_dialog_contents(
    item: &CipherItem,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> LinearLayout {
    let identity = match &item.data {
        CipherData::Identity(id) => id,
        _ => unreachable!(),
    };

    let mut ll = LinearLayout::vertical();

    add_label_value_text(&mut ll, "Name", &item.name, enc_key, mac_key);

    add_label_value_text(&mut ll, "Title", &identity.title, enc_key, mac_key);
    add_label_value_text(
        &mut ll,
        "First name",
        &identity.first_name,
        enc_key,
        mac_key,
    );
    add_label_value_text(
        &mut ll,
        "Middle name",
        &identity.middle_name,
        enc_key,
        mac_key,
    );
    add_label_value_text(&mut ll, "Last name", &identity.last_name, enc_key, mac_key);

    add_label_value_text(&mut ll, "Phone", &identity.phone, enc_key, mac_key);
    add_label_value_text(&mut ll, "Email", &identity.email, enc_key, mac_key);

    add_label_value_text(&mut ll, "Address 1", &identity.address_1, enc_key, mac_key);
    add_label_value_text(&mut ll, "Address 2", &identity.address_2, enc_key, mac_key);
    add_label_value_text(&mut ll, "Address 3", &identity.address_3, enc_key, mac_key);
    add_label_value_text(
        &mut ll,
        "Postal code",
        &identity.postal_code,
        enc_key,
        mac_key,
    );
    add_label_value_text(&mut ll, "City", &identity.city, enc_key, mac_key);
    add_label_value_text(&mut ll, "State", &identity.state, enc_key, mac_key);
    add_label_value_text(&mut ll, "Country", &identity.country, enc_key, mac_key);

    add_label_value_text(&mut ll, "Company", &identity.company, enc_key, mac_key);
    add_label_value_text(&mut ll, "SSN", &identity.ssn, enc_key, mac_key);
    add_label_value_text(
        &mut ll,
        "License number",
        &identity.license_number,
        enc_key,
        mac_key,
    );
    add_label_value_text(
        &mut ll,
        "Passport number",
        &identity.passport_number,
        enc_key,
        mac_key,
    );
    add_label_value_text(&mut ll, "Username", &identity.username, enc_key, mac_key);

    add_label_value_text(&mut ll, "Notes", &item.notes, enc_key, mac_key);

    ll
}

fn add_label_value_text(
    ll: &mut LinearLayout,
    name: &str,
    value: &Cipher,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) {
    ll.add_child(TextView::new(name));
    ll.add_child(value_textview(value, enc_key, mac_key));
}

fn value_textview(
    cipher: &Cipher,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> PaddedView<TextView> {
    let tv = TextView::new(cipher.decrypt_to_string(enc_key, mac_key)).style(*VALUE_STYLE);
    PaddedView::new(Margins::tb(0, 1), tv)
}

fn value_secret_textview(
    cipher: &Cipher,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> PaddedView<SecretTextView> {
    let tv = SecretTextView::new(cipher.decrypt_to_string(enc_key, mac_key)).style(*VALUE_STYLE);
    PaddedView::new(Margins::tb(0, 1), tv)
}
