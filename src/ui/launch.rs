use std::sync::Arc;

use cursive::{
    theme::BaseColor, theme::Color, theme::PaletteColor::*, theme::Theme, Cursive, CursiveRunnable,
};

use crate::profile::{GlobalSettings, ProfileData, ProfileStore};

use super::{autolock, data::UserData, login::login_dialog};

pub fn launch(profile: String, server_url: Option<String>, accept_invalid_certs: bool) {
    let (global_settings, profile_data, profile_store) =
        load_profile(profile, server_url, accept_invalid_certs);
    let profile_name = global_settings.profile.clone();

    let mut siv = cursive::default();
    siv.set_theme(custom_theme());
    let autolocker =
        autolock::start_autolocker(siv.cb_sink().clone(), global_settings.autolock_duration);
    siv.set_user_data(UserData::new(
        Arc::new(global_settings),
        Arc::new(profile_store),
        autolocker,
    ));

    siv.add_global_callback('§', Cursive::toggle_debug_console);
    cursive::logger::init();
    log::set_max_level(log::LevelFilter::Info);

    siv.add_layer(login_dialog(&profile_name, profile_data.saved_email, false));

    run(siv);
}

fn run(mut cursive: CursiveRunnable) {
    let mut cursive = cursive.runner();

    cursive.refresh();

    while cursive.is_running() {
        let got_event = cursive.step();

        if got_event {
            cursive.with_user_data(|ud: &mut UserData| {
                if let Some(ud) = ud.with_unlocked_state() {
                    ud.autolocker()
                        .lock()
                        .unwrap()
                        .update_next_autolock_time(false)
                }
            });
        }
    }
}

fn load_profile(
    profile_name: String,
    server_url: Option<String>,
    accept_invalid_certs: bool,
) -> (GlobalSettings, ProfileData, ProfileStore) {
    let profile_store = ProfileStore::new(&profile_name);
    let mut profile_data = profile_store.load().unwrap_or_default();

    let global_settings = GlobalSettings {
        profile: profile_name,
        server_url: server_url.unwrap_or(profile_data.server_url),
        autolock_duration: profile_data.autolock_duration,
        device_id: profile_data.device_id.clone(),
        accept_invalid_certs,
    };

    // Write new settings
    profile_data.server_url = global_settings.server_url.clone();
    profile_store
        .store(&profile_data)
        .expect("Failed to write profile settings");

    (global_settings, profile_data, profile_store)
}

fn custom_theme() -> Theme {
    let mut t = Theme::default();

    t.palette[Background] = Color::TerminalDefault;
    t.palette[View] = Color::parse("#f0f4f7").unwrap();
    t.palette[Primary] = Color::Dark(BaseColor::Black);
    t.palette[Secondary] = Color::parse("#525252").unwrap();
    t.palette[TitlePrimary] = Color::parse("#1b98e0").unwrap();
    t.palette[Highlight] = Color::parse("#126391").unwrap();
    t.palette[HighlightInactive] = Color::parse("#233d4d").unwrap();
    t.palette[HighlightText] = Color::parse("#f0f4f7").unwrap();

    t
}
