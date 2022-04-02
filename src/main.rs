use clap::Parser;
use wden::profile::ProfileStore;

fn try_read_profile_name(input: &str) -> Result<String, anyhow::Error> {
    if input
        .chars()
        .any(|c| !c.is_ascii_lowercase() && !c.is_digit(10) && c != '_' && c != '-')
    {
        Err(anyhow::anyhow!("Invalid profile name. Profile names can only include lowercase alphanumeric characters, dashes (-) and underscores (_)."))
    } else {
        Ok(input.to_string())
    }
}

#[derive(Parser)]
#[clap(version)]
struct Opts {
    /// Sets the profile that will be used. Profile names can only
    /// include lowercase alphanumeric characters, dashes (-) and
    /// underscores (_).
    #[clap(short, long, default_value = "default", parse(try_from_str = try_read_profile_name))]
    profile: String,

    /// Sets the Bitwarden server url.
    /// If not set, the url stored in the profile
    /// will be used. If a new profile is created without
    /// a server url set, https://vault.bitwarden.com will be used.
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

    wden::ui::launch(opts.profile, opts.server_url);
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
