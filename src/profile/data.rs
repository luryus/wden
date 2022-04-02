use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
pub struct ProfileData {
    pub saved_email: Option<String>,
    #[serde(default = "get_default_server_url")]
    pub server_url: String,
    pub saved_two_factor_token: Option<String>,
    pub autolock_duration: Duration,
    pub device_id: String,
}

fn get_default_server_url() -> String {
    crate::bitwarden::api::DEFAULT_SERVER_URL.to_string()
}

impl Default for ProfileData {
    fn default() -> Self {
        ProfileData {
            saved_email: None,
            server_url: get_default_server_url(),
            saved_two_factor_token: None,
            autolock_duration: Duration::from_secs(5 * 60), // 5 minutes
            device_id: format!("{}", Uuid::new_v4()),
        }
    }
}
