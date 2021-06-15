use crate::bitwarden::{
    api,
    cipher::{self, EncryptionKey, MacKey},
};
use cipher::decrypt_symmetric_keys;
use directories_next::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

pub struct GlobalSettings {
    pub server_url: String,
    pub profile: String,
}

pub struct UserData {
    pub global_settings: GlobalSettings,
    pub profile_store: ProfileStore,
    pub email: Option<String>,
    pub master_key: Option<cipher::MasterKey>,
    pub master_password_hash: Option<cipher::MasterPasswordHash>,
    pub token: Option<api::TokenResponse>,
    pub vault_data: Option<HashMap<String, api::CipherItem>>,
}

impl UserData {
    pub fn new(global_settings: GlobalSettings, profile_store: ProfileStore) -> UserData {
        UserData {
            global_settings,
            profile_store,
            email: None,
            master_key: None,
            master_password_hash: None,
            token: None,
            vault_data: None,
        }
    }

    pub fn decrypt_keys(&self) -> Option<(EncryptionKey, MacKey)> {
        let token_key = &self.token.as_ref()?.key;
        let master_key = self.master_key?;
        decrypt_symmetric_keys(token_key, master_key).ok()
    }
}

#[derive(Deserialize, Serialize)]
pub struct ProfileData {
    pub saved_email: Option<String>,
    #[serde(default = "get_default_server_url")]
    pub server_url: String,
}

fn get_default_server_url() -> String {
    crate::bitwarden::api::DEFAULT_SERVER_URL.to_string()
}

impl Default for ProfileData {
    fn default() -> Self {
        ProfileData {
            saved_email: None,
            server_url: get_default_server_url(),
        }
    }
}

pub struct ProfileStore {
    config_dir: PathBuf,
    profile_config_file: PathBuf,
}

impl ProfileStore {
    pub fn new(profile_name: &str) -> ProfileStore {
        let dirs = ProjectDirs::from("com.koskela", "", "bitwarden-tui").unwrap();

        let config_dir = dirs.config_dir().to_path_buf();
        let profile_config_file = config_dir.join(format!("{}.json", profile_name));

        ProfileStore {
            config_dir,
            profile_config_file,
        }
    }

    pub fn load(&self) -> std::io::Result<ProfileData> {
        let contents = std::fs::read(&self.profile_config_file)?;
        let parsed = serde_json::from_slice(&contents)?;

        Ok(parsed)
    }

    pub fn store(&self, data: &ProfileData) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        let serialized = serde_json::to_vec_pretty(data)?;

        std::fs::write(&self.profile_config_file, serialized)
    }

    pub fn edit<F>(&self, editor: F) -> std::io::Result<()>
    where
        F: FnOnce(&mut ProfileData) -> (),
    {
        // Load existing file for mutation
        let mut data = self.load()?;
        // Make changes
        editor(&mut data);
        // Store the edited data
        self.store(&data)
    }
}
