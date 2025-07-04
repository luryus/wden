use crate::{
    bitwarden::{
        api::{self, CipherItem, Collection, Organization, TokenResponseSuccess},
        apikey::ApiKey,
        cipher::{self, EncMacKeys, MasterKey, MasterPasswordHash, PbkdfParameters},
    },
    profile::{GlobalSettings, ProfileStore},
};
use anyhow::Context;
use cipher::decrypt_symmetric_keys;
use maybe_owned::MaybeOwned;
use rayon::iter::{ParallelBridge, ParallelIterator};

use std::{
    collections::HashMap,
    fmt::Display,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use super::{autolock::Autolocker, collections::CollectionSelection};

macro_rules! get_state_data {
    ($app_state_data: expr, $state: path) => {{
        match $app_state_data {
            $state(a) => a,
            _ => panic!(
                "App not in expected state: requested {}, was {}",
                stringify!($state),
                $app_state_data
            ),
        }
    }};
}

pub struct LoggedOut;

pub struct LoggingIn {
    email: Arc<String>,
    pbkdf: Arc<PbkdfParameters>,
    master_key: Arc<cipher::MasterKey>,
    master_password_hash: Arc<cipher::MasterPasswordHash>,
    api_key: Option<Arc<ApiKey>>,
}

pub struct Refreshing {
    email: Arc<String>,
    pbkdf: Arc<PbkdfParameters>,
    master_key: Arc<cipher::MasterKey>,
    api_key: Option<Arc<ApiKey>>,
}

impl From<LoggingIn> for Refreshing {
    fn from(logging_in: LoggingIn) -> Self {
        Self {
            email: logging_in.email,
            pbkdf: logging_in.pbkdf,
            master_key: logging_in.master_key,
            api_key: logging_in.api_key,
        }
    }
}

pub struct LoggedIn {
    refreshing_data: Refreshing,
    token: Arc<TokenResponseSuccess>,
}

impl LoggedIn {
    fn decrypt_keys(&self) -> Option<EncMacKeys> {
        let token_key = &self.token.key;
        let master_key = &self.refreshing_data.master_key;
        decrypt_symmetric_keys(token_key, master_key).ok()
    }
}

pub struct Unlocked {
    logged_in_data: LoggedIn,
    vault_data: Arc<HashMap<String, CipherItem>>,
    organizations: Arc<HashMap<String, Organization>>,
    collections: Arc<HashMap<String, Collection>>,
}

impl Unlocked {
    fn decrypt_organization_keys(
        &self,
        organization_id: &str,
        user_keys: &EncMacKeys,
    ) -> anyhow::Result<EncMacKeys> {
        let organization = &self
            .organizations
            .get(organization_id)
            .with_context(|| format!("Org not found with id {organization_id}"))?;

        // Organization.key is encrypted with the user private (RSA) key,
        // get that first
        let user_private_key = &self.logged_in_data.token.private_key;
        let decrypted_private_key = user_private_key.decrypt(user_keys)?.into();

        // Then use the private key to decrypt the organization key
        let org_key = cipher::decrypt_org_keys(&decrypted_private_key, &organization.key)?;
        Ok(org_key)
    }

    fn get_keys_for_item(&self, item: &api::CipherItem) -> Option<EncMacKeys> {
        let user_keys = self.logged_in_data.decrypt_keys()?;
        let resolved =
            crate::bitwarden::keys::resolve_item_keys(item, user_keys.into(), |oid, uk| {
                self.decrypt_organization_keys(oid, uk)
                    .inspect_err(|e| log::warn!("Org key decryption failed: {e}"))
                    .ok()
                    .map(|k| k.into())
            })?;

        match resolved {
            MaybeOwned::Owned(keys) => Some(keys),
            MaybeOwned::Borrowed(_) => {
                panic!("Bug: get_keys_for_item should only handle owned keys")
            }
        }
    }

    fn get_keys_for_collection(&self, collection: &Collection) -> Option<EncMacKeys> {
        let user_keys = self.logged_in_data.decrypt_keys()?;
        self.decrypt_organization_keys(&collection.organization_id, &user_keys)
            .inspect_err(|e| log::warn!("Error decrypting org keys: {e}"))
            .ok()
    }

    fn get_org_keys_for_vault(&self) -> HashMap<&String, EncMacKeys> {
        self.logged_in_data
            .decrypt_keys()
            .map(|uk| {
                self.organizations
                    .keys()
                    .par_bridge()
                    .filter_map(|oid| {
                        self.decrypt_organization_keys(oid, &uk)
                            .map(|key| (oid, key))
                            .ok()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

pub struct Locked {
    email: Arc<String>,
    pbkdf: Arc<PbkdfParameters>,
    token: Arc<TokenResponseSuccess>,
    vault_data: Arc<HashMap<String, CipherItem>>,
    organizations: Arc<HashMap<String, Organization>>,
    collections: Arc<HashMap<String, Collection>>,
    encrypted_search_term: cipher::Cipher,
    collection_selection: CollectionSelection,
    api_key: Option<Arc<ApiKey>>,
}

pub struct Unlocking {
    logged_in_data: LoggedIn,
    vault_data: Arc<HashMap<String, CipherItem>>,
    organizations: Arc<HashMap<String, Organization>>,
    collections: Arc<HashMap<String, Collection>>,
    encrypted_search_term: cipher::Cipher,
    collection_selection: CollectionSelection,
}

enum AppStateData {
    LoggedOut(LoggedOut),
    LoggingIn(LoggingIn),
    Refreshing(Refreshing),
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
            AppStateData::Refreshing(_) => f.write_str("Refreshing"),
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

/// A pseudo-state: either LoggingIn or Refreshing
pub struct LoggingInLikeState;

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

    pub fn with_logging_in_like_state(&mut self) -> Option<StatefulUserData<LoggingInLikeState>> {
        match &self.state_data {
            AppStateData::Refreshing(_) => Some(StatefulUserData::new(self)),
            AppStateData::LoggingIn(_) => Some(StatefulUserData::new(self)),
            _ => None,
        }
    }
}

impl<'a> StatefulUserData<'a, LoggedOut> {
    pub fn into_logging_in(
        self,
        master_key: Arc<MasterKey>,
        master_password_hash: Arc<MasterPasswordHash>,
        pbkdf: Arc<PbkdfParameters>,
        email: Arc<String>,
        api_key: Option<Arc<ApiKey>>,
    ) -> StatefulUserData<'a, LoggingIn> {
        self.user_data.state_data = AppStateData::LoggingIn(LoggingIn {
            email,
            pbkdf,
            master_key,
            master_password_hash,
            api_key,
        });

        StatefulUserData::new(self.user_data)
    }
}

impl<'a> StatefulUserData<'a, LoggingIn> {
    pub fn into_logged_out(self) -> StatefulUserData<'a, LoggedOut> {
        into_logged_out_impl(self.user_data)
    }

    pub fn master_password_hash(&self) -> Arc<MasterPasswordHash> {
        let logging_in_data = get_state_data!(&self.user_data.state_data, AppStateData::LoggingIn);
        logging_in_data.master_password_hash.clone()
    }

    pub fn email(&self) -> Arc<String> {
        let logging_in_data = get_state_data!(&self.user_data.state_data, AppStateData::LoggingIn);
        logging_in_data.email.clone()
    }
}

impl<'a> StatefulUserData<'a, LoggingInLikeState> {
    pub fn into_logged_in(
        self,
        token: Arc<TokenResponseSuccess>,
    ) -> StatefulUserData<'a, LoggedIn> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);

        // LoggingIn-like: either LoggingIn or Refreshing
        let refreshing_data = match state_data {
            AppStateData::LoggingIn(logging_in) => logging_in.into(),
            _ => get_state_data!(state_data, AppStateData::Refreshing),
        };

        self.user_data.state_data = AppStateData::LoggedIn(LoggedIn {
            refreshing_data,
            token,
        });

        StatefulUserData::new(self.user_data)
    }

    pub fn into_logged_out(self) -> StatefulUserData<'a, LoggedOut> {
        into_logged_out_impl(self.user_data)
    }
}

fn into_logged_out_impl(user_data: &mut UserData) -> StatefulUserData<'_, LoggedOut> {
    user_data.autolocker.lock().unwrap().clear_autolock_time();
    user_data.state_data = AppStateData::LoggedOut(LoggedOut);
    StatefulUserData::new(user_data)
}

impl<'a> StatefulUserData<'a, LoggedIn> {
    pub fn email(&self) -> Arc<String> {
        get_state_data!(&self.user_data.state_data, AppStateData::LoggedIn)
            .refreshing_data
            .email
            .clone()
    }

    pub fn token(&self) -> Arc<TokenResponseSuccess> {
        get_state_data!(&self.user_data.state_data, AppStateData::LoggedIn)
            .token
            .clone()
    }

    pub fn api_key(&self) -> Option<Arc<ApiKey>> {
        get_state_data!(&self.user_data.state_data, AppStateData::LoggedIn)
            .refreshing_data
            .api_key
            .clone()
    }

    pub fn into_unlocked(
        self,
        vault_data: Arc<HashMap<String, CipherItem>>,
        organizations: Arc<HashMap<String, Organization>>,
        collections: Arc<HashMap<String, Collection>>,
    ) -> StatefulUserData<'a, Unlocked> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let logged_in_data = get_state_data!(state_data, AppStateData::LoggedIn);
        let unlocked_data = Unlocked {
            logged_in_data,
            vault_data,
            organizations,
            collections,
        };

        self.user_data.state_data = AppStateData::Unlocked(unlocked_data);

        StatefulUserData::new(self.user_data)
    }

    pub fn into_refreshing(self) -> StatefulUserData<'a, Refreshing> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let logged_in_data = get_state_data!(state_data, AppStateData::LoggedIn);

        self.user_data.state_data = AppStateData::Refreshing(logged_in_data.refreshing_data);

        StatefulUserData::new(self.user_data)
    }
}

impl<'a> StatefulUserData<'a, Unlocked> {
    pub fn into_locked(
        self,
        search_term: &str,
        collection_selection: CollectionSelection,
    ) -> StatefulUserData<'a, Locked> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let unlocked_data = get_state_data!(state_data, AppStateData::Unlocked);

        self.user_data
            .autolocker
            .lock()
            .unwrap()
            .clear_autolock_time();

        // Encrypt the vault view state with the current user keys
        let enc_search_term = unlocked_data
            .logged_in_data
            .decrypt_keys()
            .and_then(|user_keys| cipher::Cipher::encrypt(search_term.as_bytes(), &user_keys).ok());

        let locked_data = Locked {
            email: unlocked_data.logged_in_data.refreshing_data.email,
            pbkdf: unlocked_data.logged_in_data.refreshing_data.pbkdf,
            token: unlocked_data.logged_in_data.token,
            vault_data: unlocked_data.vault_data,
            organizations: unlocked_data.organizations,
            collections: unlocked_data.collections,
            encrypted_search_term: enc_search_term.unwrap_or_default(),
            collection_selection,
            api_key: unlocked_data.logged_in_data.refreshing_data.api_key,
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

    pub fn decrypt_keys(&self) -> Option<EncMacKeys> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocked);
        d.logged_in_data.decrypt_keys()
    }

    pub fn vault_data(&self) -> Arc<HashMap<String, CipherItem>> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocked);
        d.vault_data.clone()
    }

    pub fn collections(&self) -> Arc<HashMap<String, Collection>> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocked);
        d.collections.clone()
    }

    pub fn get_keys_for_item(&self, item: &CipherItem) -> Option<EncMacKeys> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocked);
        d.get_keys_for_item(item)
    }

    pub fn get_keys_for_collection(&self, collection: &Collection) -> Option<EncMacKeys> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocked);
        d.get_keys_for_collection(collection)
    }

    pub fn get_org_keys_for_vault(&self) -> HashMap<&String, EncMacKeys> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocked);
        d.get_org_keys_for_vault()
    }
}

impl<'a> StatefulUserData<'a, Unlocking> {
    pub fn decrypt_search_term(&self) -> Option<String> {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocking);
        d.logged_in_data
            .decrypt_keys()
            .map(|user_keys| d.encrypted_search_term.decrypt_to_string(&user_keys))
    }

    pub fn collection_selection(&self) -> CollectionSelection {
        let d = get_state_data!(&self.user_data.state_data, AppStateData::Unlocking);
        d.collection_selection.clone()
    }

    pub fn into_unlocked(self) -> StatefulUserData<'a, Unlocked> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let unlocking_data = get_state_data!(state_data, AppStateData::Unlocking);

        let unlocked_data = Unlocked {
            logged_in_data: unlocking_data.logged_in_data,
            organizations: unlocking_data.organizations,
            vault_data: unlocking_data.vault_data,
            collections: unlocking_data.collections,
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

    pub fn pbkdf(&self) -> Arc<PbkdfParameters> {
        get_state_data!(&self.user_data.state_data, AppStateData::Locked)
            .pbkdf
            .clone()
    }

    pub fn api_key(&self) -> Option<Arc<ApiKey>> {
        get_state_data!(&self.user_data.state_data, AppStateData::Locked)
            .api_key
            .clone()
    }

    pub fn into_unlocking(
        self,
        master_key: Arc<MasterKey>,
        api_key: Option<Arc<ApiKey>>,
    ) -> StatefulUserData<'a, Unlocking> {
        let state_data =
            std::mem::replace(&mut self.user_data.state_data, AppStateData::Intermediate);
        let locked_data = get_state_data!(state_data, AppStateData::Locked);

        let unlocking_data = Unlocking {
            logged_in_data: LoggedIn {
                refreshing_data: Refreshing {
                    email: locked_data.email,
                    pbkdf: locked_data.pbkdf,
                    master_key,
                    api_key,
                },
                token: locked_data.token,
            },
            organizations: locked_data.organizations,
            vault_data: locked_data.vault_data,
            collections: locked_data.collections,
            encrypted_search_term: locked_data.encrypted_search_term,
            collection_selection: locked_data.collection_selection,
        };

        self.user_data.state_data = AppStateData::Unlocking(unlocking_data);

        StatefulUserData::new(self.user_data)
    }
}
