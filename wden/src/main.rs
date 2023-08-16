use clap::{
    builder::{StringValueParser, TypedValueParser},
    Parser, ValueEnum,
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

#[derive(Clone, Copy, ValueEnum)]
enum BitwardenCloudRegion {
    Us, Eu
}

#[derive(Parser)]
#[command(version)]
struct Opts {
    /// Sets the profile that will be used. Profile names can only
    /// include lowercase alphanumeric characters, dashes (-) and
    /// underscores (_).
    #[arg(
        short, long, 
        default_value = "default", 
        value_parser=StringValueParser::new().try_map(validate_profile_name))]
    profile: String,

    /// Sets the current profile to use the given Bitwarden
    /// cloud server region.
    /// 
    /// Example: --bitwarden-cloud-region eu
    #[arg(
        long,
        conflicts_with_all=["server_url", "api_server_url", "identity_server_url"],
        help_heading=Some("Server options"))]
    bitwarden_cloud_region: Option<BitwardenCloudRegion>,

    /// Sets the current profile to use the given server url
    /// (single host).
    ///
    /// Example: --server-url https://bitwarden.example.com.
    #[arg(
        short, long, 
        conflicts_with_all=["bitwarden_cloud_region", "api_server_url", "identity_server_url"],
        help_heading=Some("Server options"))]
    server_url: Option<String>,

    /// Sets the current profile to use the given API server
    /// url. This needs to be set with --identity-server-url.
    /// 
    /// Example: --api-server-url https://api.example.com --identity-server-url https://identity.example.com
    #[arg(
        long,
        requires="identity_server_url",
        conflicts_with_all=["bitwarden_cloud_region", "server_url"],
        help_heading=Some("Server options"))]
    api_server_url: Option<String>,

    /// Sets the current profile to use the given identity server
    /// url. This needs to be set with --api-server-url.
    /// 
    /// Example: --api-server-url https://api.example.com --identity-server-url https://identity.example.com
    #[arg(
        long,
        requires="api_server_url",
        conflicts_with_all=["bitwarden_cloud_region", "server_url"],
        help_heading=Some("Server options"))]
    identity_server_url: Option<String>,

    /// Instead of starting the application,
    /// list all stored profiles
    #[arg(long)]
    list_profiles: bool,

    /// Accept invalid and untrusted (e.g. self-signed) certificates
    /// when connecting to the server. This option makes connections
    /// insecure, so avoid using it.
    /// 
    /// Note: this option is not stored in the profile settings.
    /// It must be specified every time when
    /// connecting to servers with untrusted certificates.
    #[arg(long, help_heading=Some("Advanced options"))]
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
