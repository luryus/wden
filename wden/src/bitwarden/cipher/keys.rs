use base64::prelude::*;
use hkdf::Hkdf;
use rand::RngCore;
use rsa::{RsaPublicKey, pkcs8::DecodePrivateKey};
use secure_buffer::{SecureBuffer, get_secure_buffer};
use serde::{Deserialize, Serialize, de::Visitor};
use sha2::Sha256;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::{Cipher, CipherError, PbkdfParameters, get_pbkdf};

const CREDENTIAL_LEN: usize = 256 / 8;

pub struct MasterKey(SecureBuffer<'static, CREDENTIAL_LEN>);
impl MasterKey {
    pub(super) fn new() -> Self {
        MasterKey(get_secure_buffer())
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

impl Clone for MasterKey {
    fn clone(&self) -> Self {
        let mut new_key = Self::new();
        new_key.buf_mut().copy_from_slice(self.0.as_slice());
        new_key
    }
}

impl Serialize for MasterKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.as_slice())
    }
}

impl<'de> Deserialize<'de> for MasterKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(MasterKeyBytesVisitor)
    }
}

struct MasterKeyBytesVisitor;
impl<'de> Visitor<'de> for MasterKeyBytesVisitor {
    type Value = MasterKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "exactly {} bytes", CREDENTIAL_LEN)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() != CREDENTIAL_LEN {
            Err(E::invalid_length(v.len(), &self))
        } else {
            let mut master_key = MasterKey::new();
            master_key.buf_mut().copy_from_slice(v);
            Ok(master_key)
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut master_key = MasterKey::new();
        let buf = master_key.buf_mut();
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = seq
                .next_element()?
                .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
        }
        Ok(master_key)
    }
}

pub struct MasterPasswordHash(SecureBuffer<'static, CREDENTIAL_LEN>);
impl MasterPasswordHash {
    fn new() -> Self {
        MasterPasswordHash(get_secure_buffer())
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

pub struct EncryptionKey(SecureBuffer<'static, CREDENTIAL_LEN>);
impl EncryptionKey {
    fn new() -> Self {
        Self(get_secure_buffer())
    }

    pub(super) fn data(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub struct MacKey(SecureBuffer<'static, CREDENTIAL_LEN>);
impl MacKey {
    fn new() -> Self {
        Self(get_secure_buffer())
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

    pub fn secure_generate() -> Self {
        let mut enc = EncryptionKey::new();
        let mut mac = MacKey::new();

        let mut rng = rand::thread_rng();
        rng.fill_bytes(enc.0.as_mut_slice());
        rng.fill_bytes(mac.0.as_mut_slice());

        Self(enc, mac)
    }

    pub const fn total_len() -> usize {
        2 * CREDENTIAL_LEN
    }

    pub fn store_to_slice(&self, buf: &mut [u8]) -> Result<(), CipherError> {
        if buf.len() < Self::total_len() {
            return Err(CipherError::InvalidKeyLength);
        }

        buf[..32].copy_from_slice(self.enc().data());
        buf[32..].copy_from_slice(self.mac().data());

        Ok(())
    }

    pub fn from_slice(buf: &[u8]) -> Result<Self, CipherError> {
        if buf.len() != Self::total_len() {
            return Err(CipherError::InvalidKeyLength);
        }

        let mut enc_key = EncryptionKey::new();
        let mut mac_key = MacKey::new();

        enc_key
            .0
            .as_mut_slice()
            .copy_from_slice(&buf[..CREDENTIAL_LEN]);
        mac_key
            .0
            .as_mut_slice()
            .copy_from_slice(&buf[CREDENTIAL_LEN..]);

        Ok(EncMacKeys(enc_key, mac_key))
    }

    // Serializes this EncMacKey, and encrypts it into a cipher using another EncMacKeys.
    // The result is decryptable and the keys can be extracted with
    pub fn encrypt_serialized(&self, encrypt_with: &EncMacKeys) -> Result<Cipher, CipherError> {
        const LEN: usize = EncMacKeys::total_len();
        let mut data = get_secure_buffer::<LEN>();
        self.store_to_slice(data.as_mut_slice())?;
        Cipher::encrypt(data.as_slice(), encrypt_with)
    }

    pub fn decrypt_from(
        cipher: &Cipher,
        decryption_keys: &EncMacKeys,
    ) -> Result<Self, CipherError> {
        const LEN: usize = EncMacKeys::total_len();
        let mut data = get_secure_buffer::<LEN>();
        let dec_cipher = cipher.decrypt_to(decryption_keys, data.as_mut_slice())?;
        Self::from_slice(dec_cipher)
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
    user_password: &[u8],
    pbkdf_params: &PbkdfParameters,
) -> Result<MasterKey, CipherError> {
    get_pbkdf(pbkdf_params).create_master_key(user_email, user_password)
}

pub fn create_master_password_hash(
    master_key: &MasterKey,
    user_password: &[u8],
) -> MasterPasswordHash {
    let mut res = MasterPasswordHash::new();
    pbkdf2::pbkdf2_hmac::<Sha256>(
        master_key.0.as_slice(),
        user_password,
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
    EncMacKeys::decrypt_from(key_cipher, &keys)
}

pub fn decrypt_item_keys(
    keys: &EncMacKeys,
    item_key_cipher: &Cipher,
) -> Result<EncMacKeys, CipherError> {
    EncMacKeys::decrypt_from(item_key_cipher, keys)
}

pub fn decrypt_org_keys(
    private_key: &DerPrivateKey,
    org_key_cipher: &Cipher,
) -> Result<EncMacKeys, CipherError> {
    let dec_cipher = org_key_cipher.decrypt_with_private_key(private_key)?;
    EncMacKeys::from_slice(&dec_cipher)
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
