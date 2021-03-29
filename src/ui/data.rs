use crate::bitwarden::{api, cipher};

#[derive(Default)]
pub struct UserData {
    pub email: Option<String>,
    pub master_key: Option<cipher::MasterKey>,
    pub master_password_hash: Option<cipher::MasterPasswordHash>,
    pub token: Option<api::TokenResponse>,
    pub vault_data: Option<Vec<api::CipherItem>>
}