use cursive::{Cursive, direction::Orientation, traits::Nameable, views::{Dialog, LinearLayout, NamedView, TextView}};
use cursive_table_view::{TableView, TableViewItem};
use itertools::Itertools;
use crate::bitwarden::{self, cipher::{Cipher, EncryptionKey, MacKey}};

use super::data::UserData;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum VaultTableColumn {
    Name,
    Username,
    Url
}

#[derive(Clone, Debug)]
pub struct Row {
    id: String,
    name: String,
    username: String,
    url: String
}

impl TableViewItem<VaultTableColumn> for Row {
    fn to_column(&self, column: VaultTableColumn) -> String {
        match column {
            VaultTableColumn::Name => self.name.clone(),
            VaultTableColumn::Url => self.url.clone(),
            VaultTableColumn::Username => self.username.clone()
        }
    }

    fn cmp(&self, other: &Self, column: VaultTableColumn) -> std::cmp::Ordering
    where Self: Sized {
        match column {
            VaultTableColumn::Name => self.name.cmp(&other.name),
            VaultTableColumn::Url => self.url.cmp(&other.url),
            VaultTableColumn::Username => self.username.cmp(&other.username)
        }
    }
}

pub fn vault_table_view(user_data: &mut UserData, enc_key: &EncryptionKey, mac_key: &MacKey) -> NamedView<TableView<Row, VaultTableColumn>> {
    let rows = user_data.vault_data
        .as_ref()
        .unwrap_or(&vec![])
        .iter()
        .map(|ci| Row {
            id: ci.id.clone(),
            name: cipher_to_string(ci.name.as_ref(), enc_key, mac_key),
            url: String::new(),
            username: cipher_to_string(ci.login.as_ref().and_then(|l| l.username.as_ref()), enc_key, mac_key)
        })
        .collect_vec();

    TableView::new()
        .column(VaultTableColumn::Name, "Name", |c| c)
        .column(VaultTableColumn::Username, "Username", |c| c)
        .column(VaultTableColumn::Url, "Url", |c| c)
        .default_column(VaultTableColumn::Name)
        .items(rows)
        .on_submit(|siv: &mut Cursive, _, index| {
            let sink = siv.cb_sink().clone();
            siv.call_on_name("vault_table", move |t: &mut TableView<Row, VaultTableColumn>| {
                show_item_details(sink, t.borrow_item(index).unwrap());  
            }).unwrap();
        })
        .with_name("vault_table")
}

fn show_item_details(sink: cursive::CbSink, row: &Row) {
    let item_id = row.id.clone();
    sink.send(Box::new(|siv: &mut Cursive| {
        let ud: &mut UserData = siv.user_data().unwrap();
            
        let (enc_key, mac_key) = bitwarden::cipher::decrypt_symmetric_keys(
            &ud.token.as_ref().unwrap().key, ud.master_key.unwrap()).unwrap();

        let ci = ud.vault_data.as_ref()
            .and_then(|vd| vd.iter().filter(move |ci| ci.id == item_id).next())
            .unwrap();
            
        let ll = LinearLayout::new(Orientation::Vertical)
            .child(TextView::new(cipher_to_string(ci.name.as_ref(), &enc_key, &mac_key)))
            .child(TextView::new(cipher_to_string(
                ci.login.as_ref().and_then(|l| l.username.as_ref()), &enc_key, &mac_key)))
            .child(TextView::new(cipher_to_string(
                ci.login.as_ref().and_then(|l| l.password.as_ref()), &enc_key, &mac_key)));
            
        siv.add_layer(Dialog::around(ll).button("OK", |s| { s.pop_layer(); }));

    })).unwrap();
}

fn cipher_to_string(cipher: Option<&Cipher>, enc_key: &EncryptionKey, mac_key: &MacKey) -> String {
    cipher
        .and_then(|name_cipher| name_cipher.decrypt(enc_key, mac_key).ok())
        .and_then(|s| String::from_utf8(s).ok())
        .unwrap_or(String::new())
}