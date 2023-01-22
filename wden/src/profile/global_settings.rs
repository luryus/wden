use std::time::Duration;

pub struct GlobalSettings {
    pub server_url: String,
    pub profile: String,
    pub autolock_duration: Duration,
    pub device_id: String,
    pub accept_invalid_certs: bool,
    pub always_refresh_token_on_sync: bool,
}
