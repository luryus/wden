use std::sync::Arc;

use aes::cipher::generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, digest::OutputSizeUser};

use super::{CipherError, EncMacKeys, MasterKey};

pub trait Pbkdf {
    fn create_master_key(
        &self,
        user_email: &str,
        user_password: &[u8],
    ) -> Result<MasterKey, CipherError>;

    fn derive_enc_mac_keys(&self, password: &[u8], salt: &str) -> Result<EncMacKeys, CipherError> {
        let master_key = self.create_master_key(salt, password)?;
        Ok(super::expand_master_key(&master_key))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum KeyDerivationFunction {
    Pbkdf2,
    Argon2id,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PbkdfParameters {
    pub kdf: KeyDerivationFunction,
    pub iterations: u32,
    #[serde(default)]
    pub memory_mib: u32,
    #[serde(default)]
    pub parallelism: u32,
}

pub fn get_pbkdf(params: &PbkdfParameters) -> Arc<dyn Pbkdf + Send + Sync> {
    match params.kdf {
        KeyDerivationFunction::Pbkdf2 => Arc::new(Pbkdf2 {
            hash_iterations: params.iterations,
        }),
        KeyDerivationFunction::Argon2id => Arc::new(Argon2id {
            iterations: params.iterations,
            memory_kib: params.memory_mib * 1024,
            parallelism: params.parallelism,
        }),
    }
}

pub struct Pbkdf2 {
    pub hash_iterations: u32,
}

impl Pbkdf for Pbkdf2 {
    fn create_master_key(
        &self,
        user_email: &str,
        user_password: &[u8],
    ) -> Result<MasterKey, CipherError> {
        let mut res = MasterKey::new();
        pbkdf2::pbkdf2_hmac::<Sha256>(
            user_password,
            // Email is always lowercased
            user_email.to_lowercase().as_bytes(),
            self.hash_iterations,
            res.buf_mut(),
        );
        Ok(res)
    }
}

pub struct Argon2id {
    pub iterations: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
}

impl Argon2id {
    fn hashed_salt(salt: &[u8]) -> GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize> {
        // With Argon2id, bitwarden first hashes the salt (here email) with SHA-256
        // to ensure the salt is long enough for Argon2
        let mut sha = Sha256::new();
        sha.update(salt);
        sha.finalize()
    }
}

impl Pbkdf for Argon2id {
    fn create_master_key(
        &self,
        user_email: &str,
        user_password: &[u8],
    ) -> Result<MasterKey, CipherError> {
        let salt = Self::hashed_salt(user_email.to_lowercase().as_bytes());

        let params = argon2::ParamsBuilder::new()
            .m_cost(self.memory_kib)
            .p_cost(self.parallelism)
            .t_cost(self.iterations)
            .build()
            .map_err(CipherError::InvalidKdfParameters)?;

        let kdf = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut res = MasterKey::new();
        kdf.hash_password_into(user_password, &salt, res.buf_mut())
            .map_err(CipherError::KdfError)?;
        Ok(res)
    }
}
