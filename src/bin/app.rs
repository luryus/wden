use bitwarden_tui::{ui::data::UserData, ui::{data::{ProfileData, ProfileStore}, login::login_dialog}};
use cursive::Cursive;
use clap::{AppSettings, Clap};

#[derive(Clap)]
#[clap(setting = AppSettings::ColorAuto)]
struct Opts {
    #[clap(short, long, default_value = "default")]
    profile: String,
}

#[tokio::main]
async fn main() {
    let opts: Opts = Opts::parse();

    let profile_store = ProfileStore::new(&opts.profile);
    let profile_data = profile_store
        .load()
        .unwrap_or(ProfileData::default());

    let mut siv = cursive::default();
    siv.set_user_data(UserData::new(profile_store));

    siv.add_global_callback('§', Cursive::toggle_debug_console);
    cursive::logger::init();
    log::set_max_level(log::LevelFilter::Info);

    siv.add_layer(login_dialog(&profile_data.saved_email));
    siv.run();
}
