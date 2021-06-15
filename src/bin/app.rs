use bitwarden_tui::ui::{
    data::{GlobalSettings, ProfileData, ProfileStore, UserData},
    login::login_dialog,
};
use clap::{AppSettings, Clap};
use cursive::Cursive;

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
    siv.set_user_data(UserData::new(global_settings, profile_store));

    siv.add_global_callback('§', Cursive::toggle_debug_console);
    cursive::logger::init();
    log::set_max_level(log::LevelFilter::Info);

    siv.add_layer(login_dialog(&profile_data.saved_email));
    siv.run();
}

fn load_profile() -> (GlobalSettings, ProfileData, ProfileStore) {
    let opts: Opts = Opts::parse();

    let profile_store = ProfileStore::new(&opts.profile);
    let mut profile_data = profile_store.load().unwrap_or(ProfileData::default());

    let global_settings = GlobalSettings {
        profile: opts.profile,
        server_url: opts.server_url.unwrap_or(profile_data.server_url),
    };

    // Write new settings
    profile_data.server_url = global_settings.server_url.clone();
    profile_store
        .store(&profile_data)
        .expect("Failed to write profile settings");

    (global_settings, profile_data, profile_store)
}
