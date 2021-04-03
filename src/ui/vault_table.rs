use std::collections::HashMap;

use crate::bitwarden::{
    self,
    cipher::{Cipher, EncryptionKey, MacKey},
};
use bitwarden::api::CipherData;
use cursive::{traits::Nameable, views::NamedView, Cursive};
use cursive_table_view::{TableView, TableViewItem};
use itertools::Itertools;

use super::{data::UserData, item_details::item_detail_dialog};

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum VaultTableColumn {
    ItemType,
    Name,
    Username,
    Url,
}

#[derive(Clone, Debug)]
pub struct Row {
    id: String,
    name: String,
    username: String,
    url: String,
    item_type: String,
}

impl TableViewItem<VaultTableColumn> for Row {
    fn to_column(&self, column: VaultTableColumn) -> String {
        match column {
            VaultTableColumn::ItemType => self.item_type.clone(),
            VaultTableColumn::Name => self.name.clone(),
            VaultTableColumn::Url => self.url.clone(),
            VaultTableColumn::Username => self.username.clone(),
        }
    }

    fn cmp(&self, other: &Self, column: VaultTableColumn) -> std::cmp::Ordering
    where
        Self: Sized,
    {
        match column {
            VaultTableColumn::ItemType => self.item_type.cmp(&other.item_type),
            VaultTableColumn::Name => self.name.cmp(&other.name),
            VaultTableColumn::Url => self.url.cmp(&other.url),
            VaultTableColumn::Username => self.username.cmp(&other.username),
        }
    }
}

pub fn vault_table_view(
    user_data: &mut UserData,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> NamedView<TableView<Row, VaultTableColumn>> {
    let rows = user_data
        .vault_data
        .as_ref()
        .unwrap_or(&HashMap::new())
        .iter()
        .map(|(id, ci)| Row {
            id: id.clone(),
            name: ci.name.decrypt_to_string(enc_key, mac_key),
            url: String::new(),
            username: match &ci.data {
                CipherData::Login(l) => &l.username,
                _ => &Cipher::Empty,
            }
            .decrypt_to_string(enc_key, mac_key),
            item_type: match ci.data {
                CipherData::Login(_) => "L",
                CipherData::Card(_) => "C",
                CipherData::Identity(_) => "I",
                CipherData::SecureNote => "N",
                _ => "",
            }
            .to_string(),
        })
        .collect_vec();

    TableView::new()
        .column(VaultTableColumn::ItemType, "T", |c| c.width(1))
        .column(VaultTableColumn::Name, "Name", |c| c)
        .column(VaultTableColumn::Username, "Username", |c| c)
        .column(VaultTableColumn::Url, "Url", |c| c)
        .default_column(VaultTableColumn::Name)
        .items(rows)
        .on_submit(|siv: &mut Cursive, _, index| {
            let sink = siv.cb_sink().clone();
            siv.call_on_name(
                "vault_table",
                move |t: &mut TableView<Row, VaultTableColumn>| {
                    show_item_details(sink, t.borrow_item(index).unwrap());
                },
            )
            .unwrap();
        })
        .with_name("vault_table")
}

fn show_item_details(sink: cursive::CbSink, row: &Row) {
    let item_id = row.id.clone();
    sink.send(Box::new(move |siv: &mut Cursive| {
        let ud: &mut UserData = siv.user_data().unwrap();
        let dialog = item_detail_dialog(ud, &item_id);
        siv.add_layer(dialog);
    }))
    .unwrap();
}
