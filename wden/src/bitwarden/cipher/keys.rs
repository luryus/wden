use std::pin::Pin;

use hkdf::Hkdf;
use rsa::{pkcs8::DecodePrivateKey, RsaPublicKey};
use sha2::Sha256;
use base64::prelude::*;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::{get_pbkdf, Cipher, CipherError, PbkdfParameters};


const CREDENTIAL_LEN: usize = 256 / 8;

#[derive(ZeroizeOnDrop)]
pub struct MasterKey(Pin<Box<[u8; CREDENTIAL_LEN]>>);
impl MasterKey {
    pub(super) fn new() -> Self {
        MasterKey(Box::pin([0; CREDENTIAL_LEN]))
    }

    pub(super) fn buf_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    #[cfg(test)]
    pub(super) fn from_base64(b64_data: &str) -> Result<Self, base64::DecodeSliceError> {
        let mut key = Self::new();

        let len = BASE64_STANDARD.decode_slice(b64_data, key.0.as_mut_slice())?;
        if len == key.0.len() {
            Ok(key)
        } else {
            Err(base64::DecodeSliceError::DecodeError(
                base64::DecodeError::InvalidLength(len.abs_diff(key.0.len())),
            ))
        }
    }

    #[cfg(test)]
    pub(super) fn base64_encoded(&self) -> Zeroizing<String> {
        BASE64_STANDARD.encode(self.0.as_slice()).into()
    }
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterPasswordHash(Pin<Box<[u8; CREDENTIAL_LEN]>>);
impl MasterPasswordHash {
    fn new() -> Self {
        MasterPasswordHash(Box::pin([0; CREDENTIAL_LEN]))
    }

    pub fn base64_encoded(&self) -> Zeroizing<String> {
        BASE64_STANDARD.encode(self.0.as_slice()).into()
    }
}

impl Default for MasterPasswordHash {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(ZeroizeOnDrop)]
pub struct EncryptionKey(Pin<Box<[u8; CREDENTIAL_LEN]>>);
impl EncryptionKey {
    fn new() -> Self {
        Self(Box::pin([0u8; CREDENTIAL_LEN]))
    }

    pub(super) fn data(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[derive(ZeroizeOnDrop)]
pub struct MacKey(Pin<Box<[u8; CREDENTIAL_LEN]>>);
impl MacKey {
    fn new() -> Self {
        Self(Box::pin([0u8; CREDENTIAL_LEN]))
    }

    pub(super) fn data(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub struct EncMacKeys(EncryptionKey, MacKey);
impl EncMacKeys {
    pub fn new(enc: EncryptionKey, mac: MacKey) -> Self {
        Self(enc, mac)
    }
    pub fn enc(&self) -> &EncryptionKey {
        &self.0
    }
    pub fn mac(&self) -> &MacKey {
        &self.1
    }
}

// Private key is in DER format
#[derive(ZeroizeOnDrop)]
pub struct DerPrivateKey(Vec<u8>);
impl From<Vec<u8>> for DerPrivateKey {
    fn from(data: Vec<u8>) -> Self {
        DerPrivateKey(data)
    }
}
impl DerPrivateKey {
    pub(super) fn data(&self) -> &[u8] {
        &self.0
    }

    pub fn public_key(&self) -> Result<RsaPublicKey, rsa::Error> {
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(self.data())?;
        Ok(priv_key.to_public_key())
    } 
}

pub fn create_master_key(
    user_email: &str,
    user_password: &str,
    pbkdf_params: &PbkdfParameters,
) -> Result<MasterKey, CipherError> {
    get_pbkdf(pbkdf_params).create_master_key(user_email, user_password)
}

pub fn create_master_password_hash(
    master_key: &MasterKey,
    user_password: &str,
) -> MasterPasswordHash {
    let mut res = MasterPasswordHash::new();
    pbkdf2::pbkdf2_hmac::<Sha256>(
        master_key.0.as_slice(),
        user_password.as_bytes(),
        1,
        res.0.as_mut_slice(),
    );
    res
}


pub fn decrypt_symmetric_keys(
    key_cipher: &Cipher,
    master_key: &MasterKey,
) -> Result<EncMacKeys, CipherError> {
    let keys = expand_master_key(master_key);

    let len = key_cipher.ct_len();
    let mut buf = Zeroizing::new(vec![0u8; len].into_boxed_slice());
    let dec_cipher = key_cipher.decrypt_to(&keys, &mut buf)?;

    extract_enc_mac_keys(dec_cipher)
}

pub fn decrypt_item_keys(
    keys: &EncMacKeys,
    item_key_cipher: &Cipher,
) -> Result<EncMacKeys, CipherError> {
    let len = item_key_cipher.ct_len();
    let mut buf = Zeroizing::new(vec![0u8; len].into_boxed_slice());
    let dec_cipher = item_key_cipher.decrypt_to(keys, &mut buf)?;
    extract_enc_mac_keys(dec_cipher)
}

pub fn decrypt_org_keys(
    private_key: &DerPrivateKey,
    org_key_cipher: &Cipher,
) -> Result<EncMacKeys, CipherError> {
    let dec_cipher = org_key_cipher.decrypt_with_private_key(private_key)?;
    extract_enc_mac_keys(&dec_cipher)
}

pub fn extract_enc_mac_keys(full_key: &[u8]) -> Result<EncMacKeys, CipherError> {
    // Enc key and mac key should both be 32 bytes
    if full_key.len() != 2 * CREDENTIAL_LEN {
        return Err(CipherError::InvalidKeyLength);
    }

    let mut enc_key = EncryptionKey::new();
    let mut mac_key = MacKey::new();

    enc_key.0.as_mut_slice().copy_from_slice(&full_key[..32]);
    mac_key.0.as_mut_slice().copy_from_slice(&full_key[32..]);

    Ok(EncMacKeys(enc_key, mac_key))
}

pub(super) fn expand_master_key(master_key: &MasterKey) -> EncMacKeys {
    type HkdfSha256 = Hkdf<Sha256>;

    let prk = HkdfSha256::from_prk(master_key.0.as_slice()).unwrap();

    let enc_info = "enc".as_bytes();
    let mac_info = "mac".as_bytes();

    let mut enc_key = EncryptionKey::new();
    prk.expand(enc_info, enc_key.0.as_mut_slice()).unwrap();
    let mut mac_key = MacKey::new();
    prk.expand(mac_info, mac_key.0.as_mut_slice()).unwrap();

    EncMacKeys::new(enc_key, mac_key)
}