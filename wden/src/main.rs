use clap::{
    builder::{StringValueParser, TypedValueParser},
    Parser,
};
use reqwest::Url;
use tabled::{settings::Style, Table, Tabled};
use wden::{
    bitwarden::server::{BitwardenCloudRegion, ServerConfiguration},
    profile::ProfileStore,
};

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
    server_url: Option<Url>,

    /// Sets the current profile to use the given API server
    /// url. This needs to be set with --identity-server-url.
    ///
    /// Example: --api-server-url https://api.example.com --identity-server-url https://identity.example.com
    #[arg(
        long,
        requires="identity_server_url",
        conflicts_with_all=["bitwarden_cloud_region", "server_url"],
        help_heading=Some("Server options"))]
    api_server_url: Option<Url>,

    /// Sets the current profile to use the given identity server
    /// url. This needs to be set with --api-server-url.
    ///
    /// Example: --api-server-url https://api.example.com --identity-server-url https://identity.example.com
    #[arg(
        long,
        requires="api_server_url",
        conflicts_with_all=["bitwarden_cloud_region", "server_url"],
        help_heading=Some("Server options"))]
    identity_server_url: Option<Url>,

    /// Register this wden instance using a Bitwarden API key.
    /// This option can be used to avoid login issues due to incorrect bot detection in Bitwarden cloud environments.
    #[arg(long, requires="api_key_client_secret", help_heading=Some("API Keys"))]
    api_key_client_id: Option<String>,
     
    #[arg(long, requires="api_key_client_id", help_heading=Some("API Keys"))]
    api_key_client_secret: Option<String>,

    #[arg(long, requires="api_key_client_id", help_heading=Some("API Keys"))]
    api_key_login_email: Option<String>,

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

    let server_config = if let Some(region) = opts.bitwarden_cloud_region {
        Some(ServerConfiguration::cloud(region))
    } else if let Some(url) = opts.server_url {
        Some(ServerConfiguration::single_host(url))
    } else if let Some((api_url, identity_url)) = opts.api_server_url.zip(opts.identity_server_url) {
        Some(ServerConfiguration::separate_hosts(api_url, identity_url))
    } else {
        None
    };

    if let Some(((client_id, client_secret), email)) = opts.api_key_client_id.zip(
        opts.api_key_client_secret).zip(opts.api_key_login_email) {
        store_api_keys(
            opts.profile, server_config,
            client_id, client_secret,
            email, opts.accept_invalid_certs)
            .await.unwrap();
        return;
    }

    wden::ui::launch(
        opts.profile,
        server_config,
        opts.accept_invalid_certs,
        opts.always_refresh_token_on_sync,
    );
}

#[derive(Tabled)]
struct ProfileListRow<'a> {
    #[tabled(rename = "NAME")]
    name: &'a str,
    #[tabled(rename = "SERVER")]
    server_config: &'a ServerConfiguration,
    #[tabled(rename = "SAVED EMAIL")]
    saved_email: &'a str,
}

fn list_profiles() -> std::io::Result<()> {
    let profiles = ProfileStore::get_all_profiles()?;

    if profiles.is_empty() {
        println!("No profiles found.")
    } else {
        let rows = profiles.iter().map(|(name, profile)| ProfileListRow {
            name,
            server_config: &profile.server_configuration,
            saved_email: profile.saved_email.as_deref().unwrap_or("None"),
        });

        let mut table = Table::new(rows);
        table.with(Style::blank());

        println!("{table}");
    }

    Ok(())
}

async fn store_api_keys(profile: String, server_config: Option<ServerConfiguration>, client_id: String, client_secret: String, email: String, accept_invalid_certs: bool) -> anyhow::Result<()> {
    let (global_settings, profile_data, profile_store) = wden::ui::launch::load_profile(
        profile,
        server_config,
        accept_invalid_certs,
        false,
    );

    let client = wden::bitwarden::api::ApiClient::new(
        &global_settings.server_configuration,
        &global_settings.device_id,
        global_settings.accept_invalid_certs
    );

    let res = client.get_token_with_api_key(
        &client_id, &client_secret, &email
    ).await?;

    println!("{res}");

    Ok(())
}
