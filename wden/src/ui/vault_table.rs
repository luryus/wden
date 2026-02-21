use std::time::{Duration, Instant};

use crate::bitwarden::{
    self,
    api::CipherItem,
    cipher::{Cipher, EncMacKeys},
    keys::resolve_item_keys,
};
use bitwarden::api::CipherData;
use cursive::{
    Cursive, View,
    event::Event,
    theme::{BaseColor, Color, PaletteColor},
    traits::{Finder, Nameable, Resizable},
    view::{Margins, ViewWrapper},
    views::{
        Dialog, EditView, LayerPosition, LinearLayout, OnEventView, PaddedView, Panel, TextView,
    },
    wrap_impl,
};
use cursive_table_view::{TableView, TableViewItem};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use simsearch::SimSearch;
use zeroize::ZeroizeOnDrop;

use super::{
    collections::{CollectionSelection, show_collection_filter},
    util::cursive_ext::{CursiveErrorExt, CursiveExt},
};
use super::{
    data::{StatefulUserData, Unlocked},
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
    search_term: String,
    collection_selection: CollectionSelection,
}

impl ViewWrapper for VaultView {
    wrap_impl!(self.view: OnEventView<LinearLayout>);
}

impl VaultView {
    fn new_with_filters(
        user_data: &StatefulUserData<Unlocked>,
        collection_selection: CollectionSelection,
        search_term: String,
    ) -> VaultView {
        let user_keys = user_data.decrypt_keys().unwrap();
        // Generate row items (with some decrypted data for all cipher items)
        // These are stored in user_data. Only the filter results are stored
        // as the table's rows.
        let rows = create_rows(user_data, user_keys);
        let simsearch = search::get_search_index(user_data);
        let view = vault_view(&search_term, &collection_selection, user_data);

        let mut vv = VaultView {
            view,
            rows,
            simsearch,
            collection_selection,
            search_term,
        };

        vv.update_search_results();

        vv
    }

    fn set_search_term(&mut self, term: impl Into<String>) {
        self.search_term = term.into();
        self.update_search_results();
    }

    fn set_collection_selection(
        &mut self,
        sel: CollectionSelection,
        user_data: &StatefulUserData<Unlocked>,
    ) {
        self.collection_selection = sel;
        if let Some(mut label_text_view) =
            self.find_name::<TextView>("active_collection_filter_label")
        {
            label_text_view.set_content(active_collection_filter_label_text(
                &self.collection_selection,
                user_data,
            ));
        }
        self.update_search_results();
    }

    fn update_search_results(&mut self) {
        if let Some(mut vt) = self.find_name::<TableView<Row, VaultTableColumn>>("vault_table") {
            let search_res_rows = self.search_rows();
            vt.set_items(search_res_rows);
            // Explicitly set the first row as selected. This is needed, because
            // for some reason the table view scrolls past and hides the first item
            // without this
            vt.set_selected_row(0);
        }
    }

    fn search_rows(&self) -> Vec<Row> {
        fn collection_matches(collection: &CollectionSelection, row: &Row) -> bool {
            match collection {
                CollectionSelection::All => true,
                CollectionSelection::Unassigned => row.collection_ids.is_empty(),
                CollectionSelection::Collection(coll) => row.collection_ids.contains(coll),
            }
        }

        match search::search_items(&self.search_term, &self.simsearch) {
            Some(matching_items) => matching_items
                .into_iter()
                .filter_map(|id| self.rows.iter().find(|r| r.id == id))
                .filter(|row| collection_matches(&self.collection_selection, row))
                .cloned()
                .collect(),
            None => self
                .rows
                .iter()
                .filter(|row| collection_matches(&self.collection_selection, row))
                .cloned()
                .collect(),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
enum VaultTableColumn {
    ItemType,
    Name,
    Username,
    IsInOrganization,
}

#[derive(Clone, Debug, ZeroizeOnDrop)]
struct Row {
    id: String,
    name: String,
    username: String,
    item_type: String,
    is_in_organization: bool,
    collection_ids: Vec<String>,
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

fn vault_view(
    search_term: &str,
    collection: &CollectionSelection,
    user_data: &StatefulUserData<Unlocked>,
) -> OnEventView<LinearLayout> {
    let table = vault_table_view();

    let ll = LinearLayout::vertical()
        .child(search_edit_view(search_term))
        .child(active_collection_filter_view(collection, user_data))
        .child(table)
        .weight(100)
        .child(key_hint_view());

    OnEventView::new(ll)
        .on_event('/', |siv| {
            if let Some(mut edit) = siv.find_name::<EditView>("search_edit") {
                edit.set_content("");
            }
            siv.focus_name("search_edit").unwrap();
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
            if let Err(e) = lock_vault(siv) {
                e.fatal_err_dialog(siv);
            }
        })
        .on_event('p', |siv| {
            copy_current_item_field(siv, Copyable::Password);
        })
        .on_event('u', |siv| {
            copy_current_item_field(siv, Copyable::Username);
        })
        .on_event('c', |siv| {
            show_collection_filter(siv, |siv, sel| {
                let mut vault_view = siv.find_name::<VaultView>("vault_view").unwrap();
                let user_data = siv.get_user_data().with_unlocked_state().unwrap();
                vault_view.set_collection_selection(sel, &user_data);
            });
        })
}

pub fn get_filters(cursive: &mut Cursive) -> Option<(String, CollectionSelection)> {
    let vault_view = cursive.find_name::<VaultView>("vault_view")?;
    Some((
        vault_view.search_term.to_string(),
        vault_view.collection_selection.clone(),
    ))
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
            let item_keys = ud.get_keys_for_item(ci).unwrap();
            super::clipboard::clip_expiring_string(li.password.decrypt_to_string(&item_keys), 30);
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
            let item_keys = ud.get_keys_for_item(ci).unwrap();
            super::clipboard::clip_string(li.username.decrypt_to_string(&item_keys));
            show_copy_notification(siv, "Username copied");
        }
        _ => (),
    };
}

enum Copyable {
    Password,
    Username,
}

fn search_edit_view(search_term: &str) -> impl View + use<> {
    let search_edit = EditView::new()
        .on_edit(|siv, text, _| {
            if let Some(mut vv) = siv.find_name::<VaultView>("vault_view") {
                vv.set_search_term(text);
            }
        })
        .on_submit(|siv, _| {
            siv.focus_name("vault_table")
                .expect("Focusing table failed");
        })
        .content(search_term)
        .with_name("search_edit")
        .full_width();

    LinearLayout::horizontal()
        .child(TextView::new("🔍"))
        .child(search_edit)
}

fn active_collection_filter_view(
    collection: &CollectionSelection,
    user_data: &StatefulUserData<Unlocked>,
) -> impl View + use<> {
    let label = TextView::new(active_collection_filter_label_text(collection, user_data))
        .style(PaletteColor::Secondary)
        .with_name("active_collection_filter_label");
    PaddedView::new(Margins::trbl(0, 2, 1, 2), label)
}

fn active_collection_filter_label_text(
    collection: &CollectionSelection,
    user_data: &StatefulUserData<Unlocked>,
) -> String {
    match collection {
        CollectionSelection::All => "All items".to_string(),
        CollectionSelection::Unassigned => "Collection: Unassigned".to_string(),
        CollectionSelection::Collection(collection_id) => {
            let collection_name = user_data
                .collections()
                .get(collection_id)
                .and_then(|coll| Some((coll, user_data.get_keys_for_collection(coll)?)))
                .map(|(coll, keys)| coll.name.decrypt_to_string(&keys))
                .unwrap_or_else(|| "<unknown>".to_string());
            format!("Collection: {collection_name}")
        }
    }
}

fn vault_table_view() -> impl View {
    let tv: TableView<Row, VaultTableColumn> = TableView::new()
        .sorting_disabled()
        .column(VaultTableColumn::ItemType, "T", |c| c.width(1))
        .column(VaultTableColumn::Name, "Name", |c| c)
        .column(VaultTableColumn::Username, "Username", |c| c)
        .column(VaultTableColumn::IsInOrganization, "O", |c| c.width(2))
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

    tv.with_name("vault_table").full_height()
}

fn create_rows(user_data: &StatefulUserData<Unlocked>, user_keys: EncMacKeys) -> Vec<Row> {
    let before = Instant::now();

    // Find all organization keys we will need
    let org_keys = user_data.get_org_keys_for_vault();
    let vault_data = user_data.vault_data();

    let mut rows: Vec<Row> = vault_data
        .par_iter()
        .filter_map(|(id, ci)| {
            let item_keys = resolve_item_keys(ci, (&user_keys).into(), |oid, _uk| {
                org_keys.get(oid).map(|k| k.into())
            })?;
            Some(Row {
                id: id.clone(),
                name: ci.name.decrypt_to_string(&item_keys),
                username: match &ci.data {
                    CipherData::Login(l) => &l.username,
                    _ => &Cipher::Empty,
                }
                .decrypt_to_string(&item_keys),
                item_type: match ci.data {
                    CipherData::Login(_) => "L",
                    CipherData::Card(_) => "C",
                    CipherData::Identity(_) => "I",
                    CipherData::SecureNote(_) => "N",
                    _ => "",
                }
                .to_string(),
                is_in_organization: ci.organization_id.is_some(),
                collection_ids: ci.collection_ids.clone(),
            })
        })
        .collect();
    rows.sort();

    let after = Instant::now();
    let dur = after - before;

    log::info!("create_rows: {}ms", dur.as_millis());

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
    fn hint_text(content: &str) -> impl View + use<> {
        PaddedView::new(
            Margins::lr(2, 2),
            TextView::new(content).style(Color::Light(BaseColor::Black)),
        )
    }

    LinearLayout::horizontal()
        .child(hint_text("</> Search"))
        .child(hint_text("<c> Collections"))
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
            if let Some(LayerPosition::FromBack(l)) = sc.find_layer_from_name("copy_notification")
                && l == sc.len() - 1
            {
                // If the dialog is the topmost layer, pop it
                siv.pop_layer();
            }
        }));
    });
}

pub fn show_vault(cursive: &mut Cursive) {
    show_vault_with_filters(cursive, Default::default(), Default::default())
}

pub fn show_vault_with_filters(
    cursive: &mut Cursive,
    search_term: String,
    collection_selection: CollectionSelection,
) {
    let ud = cursive.get_user_data().with_unlocked_state().unwrap();
    ud.autolocker()
        .lock()
        .unwrap()
        .update_next_autolock_time(true);
    let global_settings = ud.global_settings();

    let view =
        VaultView::new_with_filters(&ud, collection_selection, search_term).with_name("vault_view");

    let panel = Panel::new(view)
        .title(format!("Vault ({})", &global_settings.profile))
        .full_screen();

    // Clear all, and add the vault
    cursive.clear_layers();
    cursive.add_fullscreen_layer(panel);
}
