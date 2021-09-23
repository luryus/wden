use bitwarden_tui::ui::{
    autolock,
    data::{GlobalSettings, ProfileData, ProfileStore, UserData},
    login::login_dialog,
};
use clap::{AppSettings, Clap};
use cursive::{Cursive, CursiveRunnable};

#[derive(Clap)]
#[clap(setting = AppSettings::ColorAuto)]
struct Opts {
    #[clap(short, long, default_value = "default")]
    profile: String,

    #[clap(short, long)]
    server_url: Option<String>,
}

#[tokio::main]
async fn main() {
    let (global_settings, profile_data, profile_store) = load_profile();

    let mut siv = cursive::default();
    let autolocker =
        autolock::start_autolocker(siv.cb_sink().clone(), global_settings.autolock_duration);
    siv.set_user_data(UserData::new(global_settings, profile_store, autolocker));

    siv.add_global_callback('§', Cursive::toggle_debug_console);
    cursive::logger::init();
    log::set_max_level(log::LevelFilter::Info);

    siv.add_layer(login_dialog(&profile_data.saved_email));

    run(siv);
}

fn run(mut cursive: CursiveRunnable) {
    let mut cursive = cursive.runner();

    cursive.refresh();

    while cursive.is_running() {
        let got_event = cursive.step();

        if got_event {
            cursive.with_user_data(|ud: &mut UserData| {
                ud.autolocker
                    .lock()
                    .unwrap()
                    .update_next_autolock_time(false)
            });
        }
    }
}

fn load_profile() -> (GlobalSettings, ProfileData, ProfileStore) {
    let opts: Opts = Opts::parse();

    let profile_store = ProfileStore::new(&opts.profile);
    let mut profile_data = profile_store.load().unwrap_or(ProfileData::default());

    let global_settings = GlobalSettings {
        profile: opts.profile,
        server_url: opts.server_url.unwrap_or(profile_data.server_url),
        autolock_duration: profile_data.autolock_duration,
        device_id: profile_data.device_id.clone()
    };

    // Write new settings
    profile_data.server_url = global_settings.server_url.clone();
    profile_store
        .store(&profile_data)
        .expect("Failed to write profile settings");

    (global_settings, profile_data, profile_store)
}
