use std::collections::HashMap;

use crate::bitwarden::{
    self,
    cipher::{Cipher, EncryptionKey, MacKey},
};
use bitwarden::api::CipherData;
use cursive::{
    traits::{Nameable, Resizable},
    views::{EditView, LinearLayout, OnEventView, PaddedView, TextView},
    Cursive, View,
};
use cursive_table_view::{TableView, TableViewItem};
use itertools::Itertools;
use sublime_fuzzy::FuzzySearch;

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

impl PartialEq for Row {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id)
    }
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

pub fn vault_view(user_data: &mut UserData) -> impl View {
    let (enc_key, mac_key) = user_data.decrypt_keys().unwrap();
    let table = vault_table_view(user_data, &enc_key, &mac_key);

    let mut ll = LinearLayout::vertical()
        .child(filter_edit_view())
        .child(table)
        .weight(100);

    ll.set_focus_index(1).expect("Focusing table failed");

    OnEventView::new(ll).on_event('/', |siv| {
        siv.focus_name("search_edit")
            .expect("Focusing search failed");
    })
}

fn filter_edit_view() -> impl View {
    let filter_edit = EditView::new()
        .on_edit(|siv, text, _| {
            // Filter the results, update table
            if let Some(mut tv) = siv.find_name::<TableView<Row, VaultTableColumn>>("vault_table") {
                let ud: &mut UserData = siv.user_data().unwrap();
                let (enc_key, mac_key) = ud.decrypt_keys().unwrap();
                let rows = get_filtered_rows(text, ud, &enc_key, &mac_key);
                tv.set_items_stable(rows);
            }
        })
        .on_submit(|siv, _| {
            siv.focus_name("vault_table")
                .expect("Focusing table failed");
        })
        .with_name("search_edit")
        .full_width();

    let ll = LinearLayout::horizontal()
        .child(TextView::new("🔍"))
        .child(filter_edit);

    PaddedView::lrtb(0, 0, 0, 1, ll)
}

fn get_filtered_rows(
    filter: &str,
    user_data: &mut UserData,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> Vec<Row> {
    user_data
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
        .filter(|r| {
            filter.is_empty()
                || FuzzySearch::new(filter, &format!("{} {} {}", r.name, r.username, r.url))
                    .case_insensitive()
                    .best_match()
                    .is_some()
        })
        .collect_vec()
}

fn vault_table_view(
    user_data: &mut UserData,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> impl View {
    let rows = get_filtered_rows("", user_data, enc_key, mac_key);
    log::info!("Filter results: {}", rows.len());
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
        .full_height()
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
