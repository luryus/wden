use clap::{
    builder::{StringValueParser, TypedValueParser},
    Parser,
};
use wden::profile::ProfileStore;

fn validate_profile_name(value: String) -> Result<String, &'static str> {
    if value
        .chars()
        .any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_' && c != '-')
    {
        Err("Invalid profile name. Profile names can only include lowercase alphanumeric characters, dashes (-) and underscores (_).")
    } else {
        Ok(value)
    }
}

#[derive(Parser)]
#[command(version)]
struct Opts {
    /// Sets the profile that will be used. Profile names can only
    /// include lowercase alphanumeric characters, dashes (-) and
    /// underscores (_).
    #[arg(short, long, default_value = "default", value_parser=StringValueParser::new().try_map(validate_profile_name) )]
    profile: String,

    /// Sets the Bitwarden server url.
    /// If not set, the url stored in the profile
    /// will be used. If a new profile is created without
    /// a server url set, https://vault.bitwarden.com will be used.
    #[arg(short, long)]
    server_url: Option<String>,

    /// Instead of starting the application,
    /// list all stored profiles
    #[arg(long)]
    list_profiles: bool,

    /// Accept invalid and untrusted (e.g. self-signed) certificates
    /// when connecting to the server. This option makes connections
    /// insecure, so avoid using it. Note: this option is not stored
    /// in the profile settings. It must be specified every time when
    /// connecting to servers with untrusted certificates.
    #[arg(long)]
    accept_invalid_certs: bool,

    /// Debug option: always do token refresh when syncing.
    #[arg(long, hide(true))]
    always_refresh_token_on_sync: bool,
}

#[tokio::main]
async fn main() {
    let opts: Opts = Opts::parse();

    if opts.list_profiles {
        list_profiles().unwrap();
        return;
    }

    wden::ui::launch(
        opts.profile,
        opts.server_url,
        opts.accept_invalid_certs,
        opts.always_refresh_token_on_sync,
    );
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
