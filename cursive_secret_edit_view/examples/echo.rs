use cursive::{
    view::{Nameable, Resizable},
    views::{Dialog, EditView, LinearLayout, TextView},
    Cursive, CursiveExt,
};
use cursive_secret_edit_view::SecretEditView;

fn main() {
    let mut cursive = Cursive::default();

    let edit = SecretEditView::default().on_edit(|siv, _| {
        let ev = siv.find_name::<SecretEditView>("edit").unwrap();
        let con = ev.get_content().to_string();
        siv.find_name::<TextView>("label").unwrap().set_content(con);
    });

    let ll = LinearLayout::vertical()
        .child(edit.with_name("edit").fixed_size((20, 1)))
        .child(TextView::new("").with_name("label").min_size((20, 1)))
        .child(EditView::new().fixed_size((20, 1)));

    cursive.add_layer(Dialog::around(ll).title("SecretEditView"));

    cursive.run()
}
