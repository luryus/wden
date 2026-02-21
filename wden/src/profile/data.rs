use std::time::Duration;

use anyhow::Context;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::bitwarden::{
    apikey::EncryptedApiKey,
    server::{BitwardenCloudRegion, ServerConfiguration},
};

#[derive(Deserialize, Serialize)]
pub struct ProfileData {
    #[serde(default)]
    pub version: i32,
    pub saved_email: Option<String>,
    // Legacy field
    pub server_url: Option<String>,
    pub saved_two_factor_token: Option<String>,
    pub autolock_duration: Duration,
    pub device_id: String,
    #[serde(default)]
    pub server_configuration: ServerConfiguration,
    #[serde(default)]
    pub encrypted_api_key: Option<EncryptedApiKey>,
    #[serde(default)]
    pub experimental_unlock_with_biometrics: bool,
}

impl Default for ProfileData {
    fn default() -> Self {
        ProfileData {
            version: 1,
            saved_email: None,
            server_url: None,
            saved_two_factor_token: None,
            autolock_duration: Duration::from_secs(5 * 60), // 5 minutes
            device_id: format!("{}", Uuid::new_v4()),
            server_configuration: Default::default(),
            encrypted_api_key: None,
            experimental_unlock_with_biometrics: false,
        }
    }
}

impl ProfileData {
    pub fn run_migrations(mut self) -> Result<Self, anyhow::Error> {
        // Version 0: initial. Default if the version field is missing.
        // Version 1: server_url -> server_configuration

        if self.version < 1 {
            // If the server_url is the legacy Bitwarden Cloud Vault url
            // (old default), convert to US bitwarden cloud configuration.
            if let Some(url_str) = self.server_url.take() {
                if url_str == "https://vault.bitwarden.com/"
                    || url_str == "https://vault.bitwarden.com"
                {
                    self.server_configuration =
                        ServerConfiguration::cloud(BitwardenCloudRegion::US);
                } else {
                    let url = Url::parse(&url_str).context(
                        "Could not run profile file migration from v0 -> v1: invalid URL",
                    )?;
                    self.server_configuration = ServerConfiguration::single_host(url);
                }
            }
            self.version = 1;
        }

        Ok(self)
    }
}

#[cfg(test)]
mod test {
    mod migrations {
        use reqwest::Url;

        use crate::{
            bitwarden::server::{BitwardenCloudRegion, ServerConfiguration},
            profile::ProfileData,
        };

        #[test]
        fn test_mig_0_to_1_server_url_converts_to_server_configuration() {
            let test_data = vec![
                (
                    ProfileData {
                        version: 0,
                        server_url: None,
                        ..Default::default()
                    },
                    Default::default(),
                ),
                (
                    ProfileData {
                        version: 0,
                        server_url: Some("https://vault.bitwarden.com".to_owned()),
                        ..Default::default()
                    },
                    ServerConfiguration::BitwardenCloud(BitwardenCloudRegion::US),
                ),
                (
                    ProfileData {
                        version: 0,
                        server_url: Some("https://vault.bitwarden.com/".to_owned()),
                        ..Default::default()
                    },
                    ServerConfiguration::BitwardenCloud(BitwardenCloudRegion::US),
                ),
                (
                    ProfileData {
                        version: 0,
                        server_url: Some("https://foobar.example.com".to_owned()),
                        ..Default::default()
                    },
                    ServerConfiguration::single_host(
                        Url::parse("https://foobar.example.com").unwrap(),
                    ),
                ),
            ];

            for (profile, conf) in test_data {
                let migrated = profile.run_migrations().expect("Migration failed");
                assert_eq!(migrated.server_configuration, conf);
                assert_eq!(migrated.server_url, None);
                assert_eq!(migrated.version, 1);
            }
        }

        #[test]
        fn test_mig_0_to_1_server_url_invalid_migration_fails() {
            let prof = ProfileData {
                version: 0,
                server_url: Some("/relative/is/invalid".to_owned()),
                ..Default::default()
            };
            let migrated = prof.run_migrations();

            assert!(migrated.is_err())
        }
    }
}
