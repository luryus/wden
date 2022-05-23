use std::{rc::Rc, time::Duration};

use crate::bitwarden::{
    self,
    api::CipherItem,
    cipher::{Cipher, EncryptionKey, MacKey},
};
use bitwarden::api::CipherData;
use cursive::{
    event::Event,
    theme::{BaseColor, Color},
    traits::{Finder, Nameable, Resizable},
    view::{Margins, ViewWrapper},
    views::{
        Dialog, EditView, LayerPosition, LinearLayout, OnEventView, PaddedView, Panel, TextView,
    },
    wrap_impl, Cursive, View,
};
use cursive_table_view::{TableView, TableViewItem};
use simsearch::SimSearch;
use zeroize::Zeroize;

use super::util::cursive_ext::CursiveExt;
use super::{
    data::{StatefulUserData, UnlockedMarker},
    item_details::item_detail_dialog,
    lock::lock_vault,
    search,
    sync::do_sync,
    util::cursive_ext::CursiveCallbackExt,
};

struct VaultView {
    view: OnEventView<LinearLayout>,
    rows: Vec<Row>,
    simsearch: SimSearch<String>,
}

impl ViewWrapper for VaultView {
    wrap_impl!(self.view: OnEventView<LinearLayout>);
}

impl VaultView {
    fn new(user_data: &StatefulUserData<UnlockedMarker>) -> VaultView {
        let (enc_key, mac_key) = user_data.decrypt_keys().unwrap();
        // Generate row items (with some decrypted data for all cipher items)
        // These are stored in user_data. Only the filter results are stored
        // as the table's rows.
        let rows = create_rows(user_data, &enc_key, &mac_key);
        let simsearch = search::get_search_index(user_data);
        let view = vault_view(rows.clone());

        VaultView {
            view,
            rows,
            simsearch,
        }
    }

    fn update_search_res(&mut self, term: &str) {
        if let Some(search_res_rows) = self.search_rows(term) {
            if let Some(mut vt) = self.find_name::<TableView<Row, VaultTableColumn>>("vault_table")
            {
                vt.set_items(search_res_rows);
                // Explicitly set the first row as selected. This is needed, because
                // for some reason the table view scrolls past and hides the first item
                // without this
                vt.set_selected_row(0);
            }
        }
    }

    fn search_rows(&self, term: &str) -> Option<Vec<Row>> {
        let filtered = match search::search_items(term, &self.simsearch) {
            Some(matching_items) => matching_items
                .into_iter()
                .filter_map(|id| self.rows.iter().find(|r| r.id == id))
                .cloned()
                .collect(),
            _ => self.rows.clone(),
        };
        Some(filtered)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
enum VaultTableColumn {
    ItemType,
    Name,
    Username,
    IsInOrganization,
}

#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
struct Row {
    id: String,
    name: String,
    username: String,
    item_type: String,
    is_in_organization: bool,
}

impl PartialEq for Row {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id)
    }
}
impl Eq for Row {}
impl PartialOrd for Row {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(std::cmp::Ord::cmp(&self, &other))
    }
}
impl Ord for Row {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl TableViewItem<VaultTableColumn> for Row {
    fn to_column(&self, column: VaultTableColumn) -> String {
        match column {
            VaultTableColumn::ItemType => self.item_type.clone(),
            VaultTableColumn::Name => self.name.clone(),
            VaultTableColumn::Username => self.username.clone(),
            VaultTableColumn::IsInOrganization => if self.is_in_organization {
                "👥"
            } else {
                "👤"
            }
            .to_string(),
        }
    }

    fn cmp(&self, other: &Self, column: VaultTableColumn) -> std::cmp::Ordering
    where
        Self: Sized,
    {
        match column {
            VaultTableColumn::ItemType => self.item_type.cmp(&other.item_type),
            VaultTableColumn::Name => self.name.cmp(&other.name),
            VaultTableColumn::Username => self.username.cmp(&other.username),
            VaultTableColumn::IsInOrganization => {
                self.is_in_organization.cmp(&other.is_in_organization)
            }
        }
    }
}

fn vault_view(rows: Vec<Row>) -> OnEventView<LinearLayout> {
    let table = vault_table_view(rows);

    let ll = LinearLayout::vertical()
        .child(filter_edit_view())
        .child(table)
        .weight(100)
        .child(key_hint_view());

    OnEventView::new(ll)
        .on_event('/', |siv| {
            siv.focus_name("search_edit")
                .expect("Focusing search failed");
        })
        .on_event('q', |siv| {
            let dialog = Dialog::text("Quit?")
                .dismiss_button("Cancel")
                .button("Quit", |siv| siv.quit());
            siv.add_layer(dialog);
        })
        .on_event(Event::CtrlChar('s'), |siv| {
            do_sync(siv, false);
        })
        .on_event(Event::CtrlChar('l'), |siv| {
            lock_vault(siv);
        })
        .on_event('p', |siv| {
            copy_current_item_field(siv, Copyable::Password);
        })
        .on_event('u', |siv| {
            copy_current_item_field(siv, Copyable::Username);
        })
}

pub fn get_current_search_term(cursive: &mut Cursive) -> Option<Rc<String>> {
    let edit = cursive.find_name::<EditView>("search_edit")?;
    Some(edit.get_content())
}

pub fn set_search_term(cursive: &mut Cursive, search_term: String) {
    if let Some(mut edit) = cursive.find_name::<EditView>("search_edit") {
        update_search_results(cursive, &search_term);
        edit.set_content(search_term);
    }
}

fn copy_current_item_field(siv: &mut Cursive, field: Copyable) {
    let table = siv
        .find_name::<TableView<Row, VaultTableColumn>>("vault_table")
        .unwrap();
    let row = table.borrow_item(table.item().unwrap()).unwrap();
    let ud = siv.get_user_data().with_unlocked_state().unwrap();

    let vd = ud.vault_data();
    match (vd.get(&row.id), field) {
        (
            Some(
                ci @ CipherItem {
                    data: CipherData::Login(li),
                    ..
                },
            ),
            Copyable::Password,
        ) => {
            let (enc_key, mac_key) = ud.get_keys_for_item(ci).unwrap();
            super::clipboard::clip_expiring_string(
                li.password.decrypt_to_string(&enc_key, &mac_key),
                30,
            );
            show_copy_notification(siv, "Password copied");
        }
        (
            Some(
                ci @ CipherItem {
                    data: CipherData::Login(li),
                    ..
                },
            ),
            Copyable::Username,
        ) => {
            let (enc_key, mac_key) = ud.get_keys_for_item(ci).unwrap();
            super::clipboard::clip_string(li.username.decrypt_to_string(&enc_key, &mac_key));
            show_copy_notification(siv, "Username copied");
        }
        _ => (),
    };
}

enum Copyable {
    Password,
    Username,
}

fn filter_edit_view() -> impl View {
    let filter_edit = EditView::new()
        .on_edit(|siv, text, _| update_search_results(siv, text))
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

fn update_search_results(cursive: &mut Cursive, search_term: &str) {
    // Filter the results, update table
    if let Some(mut vv) = cursive.find_name::<VaultView>("vault_view") {
        vv.update_search_res(search_term);
    }
}

fn vault_table_view(rows: Vec<Row>) -> impl View {
    let mut tv = TableView::new()
        .sorting_disabled()
        .column(VaultTableColumn::ItemType, "T", |c| c.width(1))
        .column(VaultTableColumn::Name, "Name", |c| c)
        .column(VaultTableColumn::Username, "Username", |c| c)
        .column(VaultTableColumn::IsInOrganization, "O", |c| c.width(2))
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
        });

    // Explicitly set the first row as selected. This is needed, because
    // for some reason the table view scrolls past and hides the first item
    // without this
    tv.set_selected_row(0);

    tv.with_name("vault_table").full_height()
}

fn create_rows(
    user_data: &StatefulUserData<UnlockedMarker>,
    enc_key: &EncryptionKey,
    mac_key: &MacKey,
) -> Vec<Row> {
    // Find all organization keys we will need
    let org_keys = user_data.get_org_keys_for_vault();

    let vault_data = user_data.vault_data();

    let mut rows: Vec<Row> = vault_data
        .iter()
        .filter_map(|(id, ci)| {
            let (ec, mc) = if let Some(oid) = &ci.organization_id {
                let keys = org_keys.get(oid)?;
                (&keys.0, &keys.1)
            } else {
                (enc_key, mac_key)
            };
            Some(Row {
                id: id.clone(),
                name: ci.name.decrypt_to_string(ec, mc),
                username: match &ci.data {
                    CipherData::Login(l) => &l.username,
                    _ => &Cipher::Empty,
                }
                .decrypt_to_string(ec, mc),
                item_type: match ci.data {
                    CipherData::Login(_) => "L",
                    CipherData::Card(_) => "C",
                    CipherData::Identity(_) => "I",
                    CipherData::SecureNote => "N",
                    _ => "",
                }
                .to_string(),
                is_in_organization: ci.organization_id.is_some(),
            })
        })
        .collect();
    rows.sort();
    rows
}

fn show_item_details(cb: cursive::CbSink, row: &Row) {
    let item_id = row.id.clone();
    cb.send_msg(Box::new(move |siv: &mut Cursive| {
        let ud = siv.get_user_data().with_unlocked_state().unwrap();
        let dialog = item_detail_dialog(&ud, &item_id);
        if let Some(d) = dialog {
            siv.add_layer(d);
        }
    }));
}

fn key_hint_view() -> impl View {
    fn hint_text(content: &str) -> impl View {
        PaddedView::new(
            Margins::lr(2, 2),
            TextView::new(content).style(Color::Light(BaseColor::Black)),
        )
    }

    LinearLayout::horizontal()
        .child(hint_text("</> Search"))
        .child(hint_text("<p> Copy password"))
        .child(hint_text("<u> Copy username"))
        .child(hint_text("<q> Quit"))
        .child(hint_text("<^s> Sync"))
        .child(hint_text("<^l> Lock"))
        .full_width()
}

pub fn show_copy_notification(cursive: &mut Cursive, message: &'static str) {
    cursive.add_layer(Dialog::info(message).with_name("copy_notification"));

    let cb = cursive.cb_sink().clone();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        cb.send_msg(Box::new(|siv| {
            let sc = siv.screen_mut();
            if let Some(LayerPosition::FromBack(l)) = sc.find_layer_from_name("copy_notification") {
                if l == sc.len() - 1 {
                    // If the dialog is the topmost layer, pop it
                    siv.pop_layer();
                }
            }
        }));
    });
}

pub fn show_vault(c: &mut Cursive) {
    let ud = c.get_user_data();
    ud.autolocker()
        .lock()
        .unwrap()
        .update_next_autolock_time(true);
    let global_settings = ud.global_settings();

    let ud = ud.with_unlocked_state().unwrap();

    let view = VaultView::new(&ud).with_name("vault_view");

    let panel = Panel::new(view)
        .title(format!("Vault ({})", &global_settings.profile))
        .full_screen();

    // Clear all, and add the vault
    c.clear_layers();
    c.add_fullscreen_layer(panel);
}
