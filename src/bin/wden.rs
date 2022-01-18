use clap::Parser;
use cursive::{Cursive, CursiveRunnable};
use wden::ui::{
    autolock,
    data::{GlobalSettings, ProfileData, ProfileStore, UserData},
    login::login_dialog,
};

#[derive(Parser)]
struct Opts {
    /// Sets the profile that will be used
    #[clap(short, long, default_value = "default")]
    profile: String,

    /// Sets the Bitwarden server url.
    /// If not set, the url stored in the profile
    /// will be used. If a new profile is created without
    /// a server url set, http://localhost:8082 will be used.
    #[clap(short, long)]
    server_url: Option<String>,

    /// Instead of starting the application,
    /// list all stored profiles
    #[clap(long)]
    list_profiles: bool,
}

#[tokio::main]
async fn main() {
    let opts: Opts = Opts::parse();

    if opts.list_profiles {
        list_profiles().unwrap();
        return;
    }

    let (global_settings, profile_data, profile_store) = load_profile(opts);
    let profile_name = global_settings.profile.clone();

    let mut siv = cursive::default();
    let autolocker =
        autolock::start_autolocker(siv.cb_sink().clone(), global_settings.autolock_duration);
    siv.set_user_data(UserData::new(global_settings, profile_store, autolocker));

    siv.add_global_callback('§', Cursive::toggle_debug_console);
    cursive::logger::init();
    log::set_max_level(log::LevelFilter::Info);

    siv.add_layer(login_dialog(&profile_name, &profile_data.saved_email));

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

fn load_profile(opts: Opts) -> (GlobalSettings, ProfileData, ProfileStore) {
    let profile_store = ProfileStore::new(&opts.profile);
    let mut profile_data = profile_store.load().unwrap_or_default();

    let global_settings = GlobalSettings {
        profile: opts.profile,
        server_url: opts.server_url.unwrap_or(profile_data.server_url),
        autolock_duration: profile_data.autolock_duration,
        device_id: profile_data.device_id.clone(),
    };

    // Write new settings
    profile_data.server_url = global_settings.server_url.clone();
    profile_store
        .store(&profile_data)
        .expect("Failed to write profile settings");

    (global_settings, profile_data, profile_store)
}

fn list_profiles() -> std::io::Result<()> {
    let profiles = ProfileStore::get_all_profiles()?;

    if profiles.is_empty() {
        println!("No profiles found.")
    } else {
        for (name, profile) in profiles {
            println!(
                "- {}: Server \"{}\", saved email \"{}\"",
                name,
                profile.server_url,
                profile.saved_email.unwrap_or_else(|| "None".to_string())
            );
        }
    }

    Ok(())
}
