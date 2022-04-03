use crate::{
    bitwarden::{
        api,
        cipher::{self, extract_enc_mac_keys, EncryptionKey, MacKey},
    },
    profile::{GlobalSettings, ProfileStore},
};
use anyhow::Context;
use cipher::decrypt_symmetric_keys;
use simsearch::SimSearch;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use super::{autolock::Autolocker, vault_table};

pub struct UserData {
    pub global_settings: Arc<GlobalSettings>,
    pub profile_store: Arc<ProfileStore>,
    pub autolocker: Arc<Mutex<Autolocker>>,
    pub email: Option<Arc<String>>,
    pub master_key: Option<Arc<cipher::MasterKey>>,
    pub master_password_hash: Option<Arc<cipher::MasterPasswordHash>>,
    pub password_hash_iterations: Option<u32>,
    pub token: Option<Arc<api::TokenResponseSuccess>>,
    pub organizations: Option<Arc<HashMap<String, api::Organization>>>,
    pub vault_data: Option<Arc<HashMap<String, api::CipherItem>>>,
    pub vault_table_rows: Option<Vec<vault_table::Row>>,
    pub simsearch: Option<SimSearch<String>>,
    encrypted_search_term: Option<cipher::Cipher>,
}

impl UserData {
    pub fn new(
        global_settings: Arc<GlobalSettings>,
        profile_store: Arc<ProfileStore>,
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
            self.encrypted_search_term = search_term
                .and_then(|st| cipher::Cipher::encrypt(st.as_bytes(), &enc_key, &mac_key).ok());
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
            let org_ids: HashSet<_> = vd
                .values()
                .filter_map(|i| i.organization_id.as_ref())
                .collect();

            org_ids
                .into_iter()
                .filter_map(|oid| {
                    self.decrypt_organization_keys(oid)
                        .map(|key| (oid, key))
                        .ok()
                })
                .collect()
        })
    }
}
