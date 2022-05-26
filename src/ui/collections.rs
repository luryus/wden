use cursive::{
    views::{Dialog, SelectView},
    Cursive, view::ViewWrapper, wrap_impl
};
use serde::{Deserialize, Serialize};

use super::util::cursive_ext::CursiveExt;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CollectionSelection {
    All,
    Unassigned,
    Collection(String),
}

impl Default for CollectionSelection {
    fn default() -> Self {
        CollectionSelection::All
    }
}

struct CollectionFilterDialog {
    dialog: Dialog,
}

impl ViewWrapper for CollectionFilterDialog {
    wrap_impl!(self.dialog: Dialog);
}

impl CollectionFilterDialog {
    fn new<S: Fn(&mut Cursive, CollectionSelection) + 'static + Clone>(
        collections: Vec<(String, String)>,
        selection_callback: S,
    ) -> Self {
        let mut sel = SelectView::new();

        sel.add_item("All", CollectionSelection::All);
        sel.add_item("Unassigned", CollectionSelection::Unassigned);

        for (name, id) in collections {
            sel.add_item(name, CollectionSelection::Collection(id));
        }

        let cb2 = selection_callback.clone();
        sel.set_on_submit(move |siv, sel| {
            siv.pop_layer();
            cb2(siv, sel.clone());
        });

        let dialog = Dialog::around(sel)
            .title("Collections")
            .dismiss_button("Cancel")
            .button("Reset", move |siv| {
                siv.pop_layer();
                selection_callback(siv, CollectionSelection::All)
            });

        CollectionFilterDialog { dialog }
    }
}

pub fn show_collection_filter<S>(cursive: &mut Cursive, selection_callback: S)
where
    S: Fn(&mut Cursive, CollectionSelection) + Clone + 'static,
{
    let ud = cursive.get_user_data().with_unlocked_state().unwrap();

    let collections = ud.collections();
    let org_keys = ud.get_org_keys_for_vault();

    let mut collection_items: Vec<_> = collections
        .values()
        .filter_map(|c| {
            org_keys
                .get(&c.organization_id)
                .map(|(enc, mac)| (c.name.decrypt_to_string(enc, mac), c.id.clone()))
        })
        .collect();
    collection_items.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let dialog = CollectionFilterDialog::new(collection_items, selection_callback);
    cursive.add_layer(dialog);
}
