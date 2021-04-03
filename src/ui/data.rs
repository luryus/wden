use cipher::decrypt_symmetric_keys;
use crate::bitwarden::{api, cipher::{self, EncryptionKey, MacKey}};
use std::collections::HashMap;

#[derive(Default)]
pub struct UserData {
    pub email: Option<String>,
    pub master_key: Option<cipher::MasterKey>,
    pub master_password_hash: Option<cipher::MasterPasswordHash>,
    pub token: Option<api::TokenResponse>,
    pub vault_data: Option<HashMap<String, api::CipherItem>>
}

impl UserData {
    pub fn decrypt_keys(&self) -> Option<(EncryptionKey, MacKey)> {
        let token_key = &self.token.as_ref()?.key;
        let master_key = self.master_key?;
        decrypt_symmetric_keys(token_key, master_key).ok()
    }
}