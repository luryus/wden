use std::time::Duration;

use crate::bitwarden::server::ServerConfiguration;

pub struct GlobalSettings {
    pub server_configuration: ServerConfiguration,
    pub profile: String,
    pub autolock_duration: Duration,
    pub device_id: String,
    pub accept_invalid_certs: bool,
    pub always_refresh_token_on_sync: bool,
}
