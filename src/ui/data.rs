use crate::{
    bitwarden::{
        api::{self, CipherItem, Organization, TokenResponseSuccess},
        cipher::{
            self, extract_enc_mac_keys, EncryptionKey, MacKey, MasterKey, MasterPasswordHash,
        },
    },
    profile::{GlobalSettings, ProfileStore},
};
use anyhow::Context;
use cipher::decrypt_symmetric_keys;

use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use super::autolock::Autolocker;

macro_rules! get_state_data {
    ($app_state_data: expr, $state: path) => {{
        if let $state(a) = $app_state_data {
            a
        } else {
            panic!(
                "App not in expected state: requested {}, was {}",
                stringify!($state),
                $app_state_data
            );
        }
    }};
}

pub struct LoggedOut;

pub struct LoggingIn {
    email: Arc<String>,
    password_hash_iterations: u32,
    master_key: Arc<cipher::MasterKey>,
    master_password_hash: Arc<cipher::MasterPasswordHash>,
}

pub struct LoggedIn {
    logging_in_data: LoggingIn,
    token: Arc<api::TokenResponseSuccess>,
}

impl LoggedIn {
    fn decrypt_keys(&self) -> Option<(EncryptionKey, MacKey)> {
        let token_key = &self.token.key;
        let master_key = &self.logging_in_data.master_key;
        decrypt_symmetric_keys(token_key, master_key).ok()
    }
}

pub struct Unlocked {
    logged_in_data: LoggedIn,
    vault_data: Arc<HashMap<String, api::CipherItem>>,
    organizations: Arc<HashMap<String, api::Organization>>,
}

impl Unlocked {
    fn decrypt_organization_keys(
        &self,
        organization_id: &str,
    ) -> anyhow::Result<(EncryptionKey, MacKey)> {
        let organization = &self
            .organizations
            .get(organization_id)
            .with_context(|| format!("Org not found with id {}", organization_id))?;

        // Organization.key is encrypted with the user private (RSA) key,
        // get that first
        let (user_enc_key, user_mac_key) = self
            .logged_in_data
            .decrypt_keys()
            .context("User key decryption failed")?;
        let user_private_key = &self.logged_in_data.token.private_key;
        let decrypted_private_key = user_private_key
            .decrypt(&user_enc_key, &user_mac_key)?
            .into();

        // Then use the private key to decrypt the organization key
        let full_org_key = organization
            .key
            .decrypt_with_private_key(&decrypted_private_key)?;

        Ok(extract_enc_mac_keys(&full_org_key)?)
    }

    fn get_keys_for_item(&self, item: &api::CipherItem) -> Option<(EncryptionKey, MacKey)> {
        if let Some(oid) = &item.organization_id {
            let res = self.decrypt_organization_keys(oid);
            match res {
                Ok(k) => Some(k),
                Err(e) => {
                    log::warn!("Error decrypting org keys: {}", e);
                    None
                }
            }
        } else {
            // No organization, use user's keys
            self.logged_in_data.decrypt_keys()
        }
    }

    fn get_org_keys_for_vault(&self) -> HashMap<&String, (EncryptionKey, MacKey)> {
        let org_ids: HashSet<_> = self
            .vault_data
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
    }
}

pub struct Locked {
    email: Arc<String>,
    password_hash_iterations: u32,
    token: Arc<api::TokenResponseSuccess>,
    vault_data: Arc<HashMap<String, api::CipherItem>>,
    organizations: Arc<HashMap<String, api::Organization>>,
    encrypted_search_term: cipher::Cipher,
}

pub struct Unlocking {
    pub logged_in_data: LoggedIn,
    pub vault_data: Arc<HashMap<String, api::CipherItem>>,
    pub organizations: Arc<HashMap<String, api::Organization>>,
    pub encrypted_search_term: cipher::Cipher,
}

enum AppStateData {
    LoggedOut(LoggedOut),
    LoggingIn(LoggingIn),
    LoggedIn(LoggedIn),
    Unlocked(Unlocked),
    Locked(Locked),
    Unlocking(Unlocking),

    // An intermediate helper state used for moving the data values
    // from behind references
    Intermediate,
}

impl Display for AppStateData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppStateData::LoggedOut(_) => f.write_str("LoggedOut"),
            AppStateData::LoggingIn(_) => f.write_str("LoggingIn"),
            AppStateData::LoggedIn(_) => f.write_str("LoggedIn"),
            AppStateData::Unlocked(_) => f.write_str("Unlocked"),
            AppStateData::Locked(_) => f.write_str("Locked"),
            AppStateData::Unlocking(_) => f.write_str("Unlocking"),
            AppStateData::Intermediate => f.write_str("Intermediate"),
        }
    }
}

pub struct UserData {
    global_settings: Arc<GlobalSettings>,
    profile_store: Arc<ProfileStore>,
    autolocker: Arc<Mutex<Autolocker>>,
    state_data: AppStateData,
}

pub struct StatefulUserData<'a, T> {
    user_data: &'a mut UserData,
    state: PhantomData<T>,
}

impl<'a, T> StatefulUserData<'a, T> {
    fn new(user_data: &'a mut UserData) -> Self {
        Self {
            user_data,
            state: PhantomData,
        }
    }

    pub fn global_settings(&self) -> Arc<GlobalSettings> {
        self.user_data.global_settings.clone()
    }

    pub fn profile_store(&self) -> Arc<ProfileStore> {
        self.user_data.profile_store.clone()
    }

    pub fn autolocker(&self) -> Arc<Mutex<Autolocker>> {
        self.user_data.autolocker.clone()
    }
}

impl UserData {
    pub fn new(
        global_settings: Arc<GlobalSettings>,
        profile_store: Arc<ProfileStore>,
        autolocker: Arc<Mutex<Autolocker>>,
    ) -> UserData {
        let state = AppStateData::LoggedOut(LoggedOut);
        UserData {
            autolocker,
            profile_store,
            global_settings,
            state_data: state,
        }
    }

    pub fn with_logged_out_state(&mut self) -> Option<StatefulUserData<LoggedOut>> {
        match &self.state_data {
            &AppStateData::LoggedOut(_) => Some(StatefulUserData::new(self)),
            _ => None,
        }
    }

    pub fn with_logging_in_state(&mut self) -> Option<StatefulUserData<LoggingIn>> {
        match &self.state_data {
            &AppStateData::LoggingIn(_) => Some(StatefulUserData::new(self)),
            _ => None,
        }
    }

    pub fn with_logged_in_state(&mut self) -> Option<StatefulUserData<LoggedIn>> {
        match &self.state_data {
            &AppStateData::LoggedIn(_) => Some(StatefulUserData::new(self)),
            _ => None,
        }
    }

    pub fn with_unlocked_state(&mut self) -> Option<StatefulUserData<Unlocked>> {
        match &self.state_data {
            &AppStateData::Unlocked(_) => Some(StatefulUserData::new(self)),
            _ => None,
        }
    }

    pub fn with_locked_state(&mut self) -> Option<StatefulUserData<Locked>> {
        match &self.state_data {
            &AppStateData::Locked(_) => Some(StatefulUserData::new(self)),
            _ => None,
        }
    }
}

impl<'a> StatefulUserData<'a, LoggedOut> {
    pub fn into_logging_in(
        self,
        master_key: Arc<MasterKey>,
        master_password_hash: Arc<MasterPasswordHash>,
        password_hash_iterations: u32,
        email: Arc<String>,
    ) -> StatefulUserData<'a, LoggingIn> {
        self.user_data.state_data = AppStateData::LoggingIn(LoggingIn {
            email,
            password_hash_iterations,
            master_key,
            master_password_hash,
        });

        StatefulUserData::new(self.user_data)
    }
}

impl<'a> StatefulUserData<'a, LoggingIn> {
    pub fn into_logged_out(self) -> StatefulUserData<'a, LoggedOut> {
        self.user_data
            .autolocker
            .lock()
            .unwrap()
            .clear_autolock_time();
        self.user_data.state_data = AppStateData::LoggedOut(LoggedOut);
        StatefulUserData::new(self.user_data)
    }

    pub fn into_logged_in(
        self,
        token: Arc<TokenResponseSuccess>,
    ) -> StatefulUserData<'a, LoggedIn> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let logging_in_data = get_state_data!(state_data, AppStateData::LoggingIn);

        self.user_data.state_data = AppStateData::LoggedIn(LoggedIn {
            logging_in_data,
            token,
        });

        StatefulUserData::new(self.user_data)
    }

    pub fn master_password_hash(&self) -> Arc<MasterPasswordHash> {
        let logging_in_data = get_state_data!(&self.user_data.state_data, AppStateData::LoggingIn);
        logging_in_data.master_password_hash.clone()
    }
}

impl<'a> StatefulUserData<'a, LoggedIn> {
    pub fn email(&self) -> Arc<String> {
        get_state_data!(&self.user_data.state_data, AppStateData::LoggedIn)
            .logging_in_data
            .email
            .clone()
    }

    pub fn token(&self) -> Arc<TokenResponseSuccess> {
        get_state_data!(&self.user_data.state_data, AppStateData::LoggedIn)
            .token
            .clone()
    }

    pub fn into_unlocked(
        self,
        vault_data: Arc<HashMap<String, CipherItem>>,
        organizations: Arc<HashMap<String, Organization>>,
    ) -> StatefulUserData<'a, Unlocked> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let logged_in_data = get_state_data!(state_data, AppStateData::LoggedIn);
        let unlocked_data = Unlocked {
            logged_in_data,
            vault_data,
            organizations,
        };

        self.user_data.state_data = AppStateData::Unlocked(unlocked_data);

        StatefulUserData::new(self.user_data)
    }

    pub fn into_logging_in(self) -> StatefulUserData<'a, LoggingIn> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let logged_in_data = get_state_data!(state_data, AppStateData::LoggedIn);

        self.user_data.state_data = AppStateData::LoggingIn(logged_in_data.logging_in_data);

        StatefulUserData::new(self.user_data)
    }
}

impl<'a> StatefulUserData<'a, Unlocked> {
    pub fn into_locked(self, search_term: Option<&str>) -> StatefulUserData<'a, Locked> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let unlocked_data = get_state_data!(state_data, AppStateData::Unlocked);

        self.user_data
            .autolocker
            .lock()
            .unwrap()
            .clear_autolock_time();

        // Encrypt the vault view state with the current user keys
        let enc_search_term = search_term
            .zip(unlocked_data.logged_in_data.decrypt_keys())
            .and_then(|(st, (enc_key, mac_key))| {
                cipher::Cipher::encrypt(st.as_bytes(), &enc_key, &mac_key).ok()
            });

        let locked_data = Locked {
            email: unlocked_data.logged_in_data.logging_in_data.email,
            password_hash_iterations: unlocked_data
                .logged_in_data
                .logging_in_data
                .password_hash_iterations,
            token: unlocked_data.logged_in_data.token,
            vault_data: unlocked_data.vault_data,
            encrypted_search_term: enc_search_term.unwrap_or_default(),
            organizations: unlocked_data.organizations,
        };

        self.user_data.state_data = AppStateData::Locked(locked_data);

        StatefulUserData::new(self.user_data)
    }

    pub fn into_logged_in(self) -> StatefulUserData<'a, LoggedIn> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let unlocked_data = get_state_data!(state_data, AppStateData::Unlocked);
        self.user_data
            .autolocker
            .lock()
            .unwrap()
            .clear_autolock_time();
        self.user_data.state_data = AppStateData::LoggedIn(unlocked_data.logged_in_data);

        StatefulUserData::new(self.user_data)
    }

    pub fn decrypt_keys(&self) -> Option<(EncryptionKey, MacKey)> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocked);
        d.logged_in_data.decrypt_keys()
    }

    pub fn vault_data(&self) -> Arc<HashMap<String, CipherItem>> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocked);
        d.vault_data.clone()
    }

    pub fn get_keys_for_item(&self, item: &CipherItem) -> Option<(EncryptionKey, MacKey)> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocked);
        d.get_keys_for_item(item)
    }

    pub fn get_org_keys_for_vault(&self) -> HashMap<&String, (EncryptionKey, MacKey)> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocked);
        d.get_org_keys_for_vault()
    }
}

impl<'a> StatefulUserData<'a, Unlocking> {
    pub fn decrypt_search_term(&self) -> Option<String> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocking);
        d.logged_in_data
            .decrypt_keys()
            .map(|(ec, mc)| d.encrypted_search_term.decrypt_to_string(&ec, &mc))
    }

    pub fn into_unlocked(self) -> StatefulUserData<'a, Unlocked> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let unlocking_data = get_state_data!(state_data, AppStateData::Unlocking);

        let unlocked_data = Unlocked {
            logged_in_data: unlocking_data.logged_in_data,
            organizations: unlocking_data.organizations,
            vault_data: unlocking_data.vault_data,
        };

        self.user_data.state_data = AppStateData::Unlocked(unlocked_data);

        StatefulUserData::new(self.user_data)
    }
}

impl<'a> StatefulUserData<'a, Locked> {
    pub fn email(&self) -> Arc<String> {
        get_state_data!(&self.user_data.state_data, AppStateData::Locked)
            .email
            .clone()
    }

    pub fn token(&self) -> Arc<TokenResponseSuccess> {
        get_state_data!(&self.user_data.state_data, AppStateData::Locked)
            .token
            .clone()
    }

    pub fn password_hash_iterations(&self) -> u32 {
        get_state_data!(&self.user_data.state_data, AppStateData::Locked).password_hash_iterations
    }

    pub fn into_unlocking(
        self,
        master_key: Arc<MasterKey>,
        master_password_hash: Arc<MasterPasswordHash>,
    ) -> StatefulUserData<'a, Unlocking> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let locked_data = get_state_data!(state_data, AppStateData::Locked);

        let unlocking_data = Unlocking {
            logged_in_data: LoggedIn {
                logging_in_data: LoggingIn {
                    email: locked_data.email,
                    password_hash_iterations: locked_data.password_hash_iterations,
                    master_key,
                    master_password_hash,
                },
                token: locked_data.token,
            },
            encrypted_search_term: locked_data.encrypted_search_term,
            organizations: locked_data.organizations,
            vault_data: locked_data.vault_data,
        };

        self.user_data.state_data = AppStateData::Unlocking(unlocking_data);

        StatefulUserData::new(self.user_data)
    }
}
