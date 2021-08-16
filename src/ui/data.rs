use crate::bitwarden::{
    api,
    cipher::{self, extract_enc_mac_keys, EncryptionKey, MacKey},
};
use anyhow::Context;
use cipher::decrypt_symmetric_keys;
use directories_next::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use super::vault_table;

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
    pub token: Option<api::TokenResponseSuccess>,
    pub organizations: Option<HashMap<String, api::Organization>>,
    pub vault_data: Option<HashMap<String, api::CipherItem>>,
    pub vault_table_rows: Option<Vec<vault_table::Row>>
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
            organizations: None,
            vault_data: None,
            vault_table_rows: None
        }
    }

    pub fn decrypt_keys(&self) -> Option<(EncryptionKey, MacKey)> {
        let token_key = &self.token.as_ref()?.key;
        let master_key = self.master_key?;
        decrypt_symmetric_keys(token_key, master_key).ok()
    }

    pub fn decrypt_organization_keys(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<(EncryptionKey, MacKey)> {
        let organization = &self
            .organizations
            .as_ref()
            .and_then(|os| os.get(organization_id))
            .with_context(|| format!("Org not found with id {}", organization_id))?;

        // Organization.key is encrypted with the user private (RSA) key,
        // get that first
        let (user_enc_key, user_mac_key) =
            self.decrypt_keys().context("User key decryption failed")?;
        let user_private_key = &self
            .token
            .as_ref()
            .map(|t| &t.private_key)
            .context("No private key")?;
        let decrypted_private_key = user_private_key.decrypt(&user_enc_key, &user_mac_key)?;

        // Then use the private key to decrypt the organization key
        let full_org_key = organization
            .key
            .decrypt_with_private_key(&decrypted_private_key)?;

        Ok(extract_enc_mac_keys(&full_org_key)?)
    }

    pub fn get_keys_for_item(&self, item: &api::CipherItem) -> Option<(EncryptionKey, MacKey)> {
        if let Some(oid) = &item.organization_id {
            let res = self.decrypt_organization_keys(oid);
            if let Err(e) = res {
                log::warn!("Error decrypting org keys: {}", e);
                return None;
            }
            res.ok()
        } else {
            // No organization, use user's keys
            self.decrypt_keys()
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct ProfileData {
    pub saved_email: Option<String>,
    #[serde(default = "get_default_server_url")]
    pub server_url: String,
    pub saved_two_factor_token: Option<String>,
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
        }
    }
}

#[derive(Clone)]
pub struct ProfileStore {
    config_dir: PathBuf,
    profile_config_file: PathBuf,
}

impl ProfileStore {
    pub fn new(profile_name: &str) -> ProfileStore {
        let dirs = ProjectDirs::from("com.lkoskela", "", "bitwarden-tui").unwrap();

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
