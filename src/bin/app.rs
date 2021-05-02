use bitwarden_tui::{bitwarden, ui::data::UserData, ui::vault_table::vault_view, ui::login::login_dialog};
use cursive::{
    traits::{Boxable},
    views::{Dialog, Panel, TextView},
    Cursive,
};

#[tokio::main]
async fn main() {
    let mut siv = cursive::default();
    siv.set_user_data(UserData::default());

    siv.add_global_callback('§', Cursive::toggle_debug_console);
    cursive::logger::init();
    log::set_max_level(log::LevelFilter::Info);

    siv.add_layer(login_dialog());
    siv.run();
}



