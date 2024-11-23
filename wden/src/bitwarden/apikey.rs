use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json;

use super::cipher::{self, get_pbkdf, Cipher, PbkdfParameters};

// OWASP recommendations as of 2024-11-19
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
const DEFAULT_PBKDF_PARAMS: PbkdfParameters = PbkdfParameters {
    kdf: cipher::KeyDerivationFunction::Argon2id,
    iterations: 2,
    memory_mib: 19,
    parallelism: 1,
};

#[derive(Serialize, Deserialize)]
pub struct ApiKey {
    pub email: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct EncryptedApiKey {
    pub encrypted_key: Cipher,
    pub pbkdf_params: PbkdfParameters,
}

impl ApiKey {
    pub fn new(email: String, client_id: String, client_secret: String) -> Self {
        Self {
            email,
            client_id,
            client_secret,
        }
    }

    pub fn serialize_to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(self).context("Serializing API key failed")
    }

    pub fn deserialize_from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(data).context("Parsing API key failed")
    }

    pub fn encrypt(
        &self,
        profile: &str,
        email: &str,
        password: &str,
    ) -> anyhow::Result<EncryptedApiKey> {
        let serialized = self.serialize_to_bytes()?;
        let keys = get_encryption_keys(profile, email, password, &DEFAULT_PBKDF_PARAMS)?;

        let cipher = Cipher::encrypt(&serialized, &keys)?;
        Ok(EncryptedApiKey {
            encrypted_key: cipher,
            pbkdf_params: DEFAULT_PBKDF_PARAMS.clone(),
        })
    }

    pub fn decrypt(
        enc_api_key: &EncryptedApiKey,
        profile: &str,
        email: &str,
        password: &str,
    ) -> Result<ApiKey, anyhow::Error> {
        let keys = get_encryption_keys(profile, email, password, &enc_api_key.pbkdf_params)?;
        let serialized_api_key = enc_api_key.encrypted_key.decrypt(&keys)?;
        let dec_api_key = ApiKey::deserialize_from_bytes(&serialized_api_key)?;
        Ok(dec_api_key)
    }
}

fn encryption_key_salt(profile: &str, email: &str) -> String {
    format!("APIKEYENCRYPTION:{}:{}", &profile, email)
}

fn get_encryption_keys(
    profile: &str,
    email: &str,
    password: &str,
    pbkdf_params: &PbkdfParameters,
) -> Result<cipher::EncMacKeys, cipher::CipherError> {
    let salt = encryption_key_salt(profile, email);
    let pbkdf = get_pbkdf(pbkdf_params);

    pbkdf.derive_enc_mac_keys(password, &salt)
}
