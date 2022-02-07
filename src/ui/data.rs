use crate::bitwarden::{
    api,
    cipher::{self, extract_enc_mac_keys, EncryptionKey, MacKey},
};
use anyhow::Context;
use cipher::decrypt_symmetric_keys;
use directories_next::ProjectDirs;
use serde::{Deserialize, Serialize};
use simsearch::SimSearch;
use std::{collections::{HashMap, HashSet}, ffi::OsString, path::Path, str::FromStr, time::Duration};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

use super::{autolock::Autolocker, vault_table};

pub struct GlobalSettings {
    pub server_url: String,
    pub profile: String,
    pub autolock_duration: Duration,
    pub device_id: String,
}

pub struct UserData {
    pub global_settings: GlobalSettings,
    pub profile_store: ProfileStore,
    pub autolocker: Arc<Mutex<Autolocker>>,
    pub email: Option<String>,
    pub master_key: Option<cipher::MasterKey>,
    pub master_password_hash: Option<cipher::MasterPasswordHash>,
    pub password_hash_iterations: Option<u32>,
    pub token: Option<api::TokenResponseSuccess>,
    pub organizations: Option<HashMap<String, api::Organization>>,
    pub vault_data: Option<HashMap<String, api::CipherItem>>,
    pub vault_table_rows: Option<Vec<vault_table::Row>>,
    pub simsearch: Option<SimSearch<String>>,
    encrypted_search_term: Option<cipher::Cipher>,
}

impl UserData {
    pub fn new(
        global_settings: GlobalSettings,
        profile_store: ProfileStore,
        autolocker: Arc<Mutex<Autolocker>>,
    ) -> UserData {
        UserData {
            global_settings,
            profile_store,
            autolocker,
            email: None,
            master_key: None,
            master_password_hash: None,
            password_hash_iterations: None,
            token: None,
            organizations: None,
            vault_data: None,
            vault_table_rows: None,
            simsearch: None,
            encrypted_search_term: None,
        }
    }

    pub fn clear_login_data(&mut self) {
        self.email = None;
        self.master_key = None;
        self.master_password_hash = None;
        self.password_hash_iterations = None;
        self.token = None;
        self.organizations = None;
        self.vault_data = None;
        self.vault_table_rows = None;
        self.simsearch = None;
        self.autolocker.lock().unwrap().clear_autolock_time();
        self.encrypted_search_term = None;
    }

    pub fn clear_data_for_locking(&mut self, search_term: Option<&str>) {
        // Encrypt the vault view state with the current user keys
        if let Some((enc_key, mac_key)) = self.decrypt_keys() {
            self.encrypted_search_term =
                search_term.and_then(|st| cipher::Cipher::encrypt(&st, &enc_key, &mac_key).ok());
        }

        // Clear keys
        self.master_key = None;
        self.master_password_hash = None;

        // Clear any plaintext data
        self.vault_table_rows = None;
        self.simsearch = None;

        // Clear autolock
        self.autolocker.lock().unwrap().clear_autolock_time();
    }

    pub fn decrypt_search_term(&mut self) -> Option<String> {
        self.encrypted_search_term
            .take()
            .and_then(|term| self.decrypt_keys().map(|(ec, mc)| (term, ec, mc)))
            .map(|(term, ec, mc)| term.decrypt_to_string(&ec, &mc))
    }

    pub fn decrypt_keys(&self) -> Option<(EncryptionKey, MacKey)> {
        let token_key = &self.token.as_ref()?.key;
        let master_key = self.master_key.as_ref()?;
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
        let decrypted_private_key = user_private_key
            .decrypt(&user_enc_key, &user_mac_key)?
            .into();

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

    pub fn get_org_keys_for_vault(&self) -> Option<HashMap<&String, (EncryptionKey, MacKey)>> {
        self.vault_data.as_ref().map(|vd| {
            let org_ids: HashSet<_> = vd.values()
                .filter_map(|i| i.organization_id.as_ref())
                .collect();

            org_ids.into_iter()
                .filter_map(|oid| {
                    self.decrypt_organization_keys(oid)
                        .map(|key| (oid, key))
                        .ok()
                })
                .collect()
        })
    }
}

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

#[derive(Clone)]
pub struct ProfileStore {
    config_dir: PathBuf,
    profile_config_file: PathBuf,
}

impl ProfileStore {
    pub fn new(profile_name: &str) -> ProfileStore {
        let config_dir = get_config_dir();
        let profile_config_file = config_dir.join(format!("{}.json", profile_name));

        ProfileStore {
            config_dir,
            profile_config_file,
        }
    }

    pub fn get_all_profiles() -> std::io::Result<Vec<(String, ProfileData)>> {
        let config_dir = get_config_dir();
        let files = match std::fs::read_dir(config_dir) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };

        let json_ext = OsString::from_str("json").unwrap();

        let profiles = files
            .filter_map(Result::ok)
            .filter(|f| f.file_type().map(|t| t.is_file()).unwrap_or(false))
            .filter(|f| f.path().extension() == Some(json_ext.as_os_str()))
            .filter_map(|f| {
                let d = Self::load_file(&f.path()).ok()?;
                Some((f.file_name().into_string().unwrap(), d))
            })
            .collect();

        Ok(profiles)
    }

    pub fn load(&self) -> std::io::Result<ProfileData> {
        Self::load_file(&self.profile_config_file)
    }

    fn load_file(path: &Path) -> std::io::Result<ProfileData> {
        let contents = std::fs::read(path)?;
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
        F: FnOnce(&mut ProfileData),
    {
        // Load existing file for mutation
        let mut data = self.load()?;
        // Make changes
        editor(&mut data);
        // Store the edited data
        self.store(&data)
    }
}

fn get_config_dir() -> PathBuf {
    let dirs = ProjectDirs::from("com.lkoskela", "", "wden").unwrap();
    dirs.config_dir().to_path_buf()
}
