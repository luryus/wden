use aes::cipher::block_padding::{Pkcs7, UnpadError};
use aes::Aes256;
use anyhow::Context;
use base64;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::digest::{InvalidLength, MacError};
use hmac::{Hmac, Mac};
use rsa::{pkcs8::DecodePrivateKey, PaddingScheme, RsaPrivateKey};
use serde::de;
use serde::{Deserialize, Deserializer};
use sha2::Sha256;
use std::convert::TryInto;
use std::fmt;

use std::str::FromStr;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const CREDENTIAL_LEN: usize = 256 / 8;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterKey([u8; CREDENTIAL_LEN]);
impl MasterKey {
    fn new() -> Self {
        MasterKey([0; CREDENTIAL_LEN])
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MasterPasswordHash([u8; CREDENTIAL_LEN]);
impl MasterPasswordHash {
    fn new() -> Self {
        MasterPasswordHash([0; CREDENTIAL_LEN])
    }

    pub fn base64_encoded(&self) -> Zeroizing<String> {
        base64::encode(&self.0).into()
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct EncryptionKey([u8; CREDENTIAL_LEN]);

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MacKey([u8; CREDENTIAL_LEN]);

// Private key is in DER format
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DerPrivateKey(Vec<u8>);
impl From<Vec<u8>> for DerPrivateKey {
    fn from(data: Vec<u8>) -> Self {
        DerPrivateKey(data)
    }
}

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Decrypted key length was invalid")]
    InvalidKeyLength,
    #[error("Cipher decryption failed")]
    CipherDecryptionFailed(#[from] anyhow::Error),
    #[error("Mac verification failed: {0}")]
    MacVerificationFailed(MacError),
    #[error("Cipher string was in an invalid format")]
    InvalidCipherStringFormat,
    #[error("Unknown cipher encryption type {0}")]
    UnknownCipherEncryptionType(String),
    #[error("Invalid key type for cipher")]
    InvalidKeyTypeForCipher,
    #[error("Invalid key or IV length for encrypting")]
    InvalidKeyOrIvLength(InvalidLength),
    #[error("Invalid padding while decrypting")]
    InvalidPadding(UnpadError),
}

pub fn create_master_key(user_email: &str, user_password: &str, hash_iterations: u32) -> MasterKey {
    let mut res = MasterKey::new();
    pbkdf2::pbkdf2::<Hmac<Sha256>>(
        user_password.as_bytes(),
        // Email is always lowercased
        user_email.to_lowercase().as_bytes(),
        hash_iterations,
        &mut res.0,
    );
    res
}

pub fn create_master_password_hash(
    master_key: &MasterKey,
    user_password: &str,
) -> MasterPasswordHash {
    let mut res = MasterPasswordHash::new();
    pbkdf2::pbkdf2::<Hmac<Sha256>>(&master_key.0, user_password.as_bytes(), 1, &mut res.0);
    res
}

pub fn decrypt_symmetric_keys(
    key_cipher: &Cipher,
    master_key: &MasterKey,
) -> Result<(EncryptionKey, MacKey), CipherError> {
    let (master_enc, master_mac) = expand_master_key(master_key);
    let dec_cipher = key_cipher.decrypt(&master_enc, &master_mac)?;

    extract_enc_mac_keys(&dec_cipher)
}

pub fn extract_enc_mac_keys(full_key: &[u8]) -> Result<(EncryptionKey, MacKey), CipherError> {
    let enc_key = full_key.iter().take(32).copied().collect::<Vec<_>>();
    let mac_key = full_key
        .iter()
        .skip(32)
        .take(32)
        .copied()
        .collect::<Vec<_>>();

    if enc_key.len() != 32 || mac_key.len() != 32 {
        return Err(CipherError::InvalidKeyLength);
    }

    let enc_key: EncryptionKey = EncryptionKey(enc_key[..].try_into().unwrap());
    let mac_key: MacKey = MacKey(mac_key[..].try_into().unwrap());

    Ok((enc_key, mac_key))
}

fn expand_master_key(master_key: &MasterKey) -> (EncryptionKey, MacKey) {
    type HkdfSha256 = Hkdf<Sha256>;

    let prk = HkdfSha256::from_prk(&master_key.0).unwrap();

    let enc_info = "enc".as_bytes();
    let mac_info = "mac".as_bytes();

    let mut enc_out = [0u8; 32];
    prk.expand(enc_info, &mut enc_out).unwrap();

    let mut mac_out = [0u8; 32];
    prk.expand(mac_info, &mut mac_out).unwrap();

    (EncryptionKey(enc_out), MacKey(mac_out))
}

#[derive(Clone)]
pub enum Cipher {
    Empty,
    Value {
        enc_type: EncType,
        iv: Vec<u8>,
        ct: Vec<u8>,
        mac: Vec<u8>,
    },
}

impl std::default::Default for Cipher {
    fn default() -> Self {
        Cipher::Empty
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "Cipher <empty>"),
            Self::Value { .. } => write!(formatter, "Cipher <value>"),
        }
    }
}

impl fmt::Debug for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Cipher: empty"),
            Self::Value { iv, ct, mac, .. } => write!(
                f,
                "Cipher: iv {} bytes, ct {} bytes, mac {} bytes",
                iv.len(),
                ct.len(),
                mac.len()
            ),
        }
    }
}

impl<'de> Deserialize<'de> for Cipher {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Cipher, D::Error> {
        Option::deserialize(deserializer)?
            .map(|s: String| s.parse().map_err(de::Error::custom))
            .unwrap_or(Ok(Cipher::Empty))
    }
}

impl FromStr for Cipher {
    type Err = CipherError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Cipher::Empty);
        }

        let (enc_type_str, rest) = s
            .split_once('.')
            .ok_or(CipherError::InvalidCipherStringFormat)?;
        let enc_type = EncType::from_str(enc_type_str)?;

        match (enc_type.has_iv(), enc_type.has_mac()) {
            (true, true) => {
                let b64_parts = rest.split('|').collect::<Vec<_>>();
                if b64_parts.len() != 3 {
                    return Err(CipherError::InvalidCipherStringFormat);
                }

                let iv =
                    base64::decode(b64_parts[0]).or(Err(CipherError::InvalidCipherStringFormat))?;
                let ct =
                    base64::decode(b64_parts[1]).or(Err(CipherError::InvalidCipherStringFormat))?;
                let mac =
                    base64::decode(b64_parts[2]).or(Err(CipherError::InvalidCipherStringFormat))?;

                Ok(Cipher::Value {
                    enc_type,
                    iv,
                    ct,
                    mac,
                })
            }
            (false, false) => {
                let iv = vec![];
                let mac = vec![];
                let ct = base64::decode(rest).or(Err(CipherError::InvalidCipherStringFormat))?;
                Ok(Cipher::Value {
                    enc_type,
                    iv,
                    ct,
                    mac,
                })
            }
            _ => unimplemented!(),
        }
    }
}

impl Cipher {
    pub fn decrypt(
        &self,
        enc_key: &EncryptionKey,
        mac_key: &MacKey,
    ) -> Result<Vec<u8>, CipherError> {
        match self {
            Self::Empty => Ok(vec![]),
            Self::Value { enc_type, .. } => match enc_type {
                EncType::AesCbc256B64 => self.decrypt_aescbc256(enc_key, mac_key),
                EncType::AesCbc128HmacSha256B64 => {
                    self.decrypt_aescbc128_hmac_sha256(enc_key, mac_key)
                }
                EncType::AesCbc256HmacSha256B64 => {
                    self.decrypt_aescbc256_hmac_sha256(enc_key, mac_key)
                }
                EncType::Rsa2048OaepSha256B64 => Err(CipherError::InvalidKeyTypeForCipher),
                EncType::Rsa2048OaepSha1B64 => Err(CipherError::InvalidKeyTypeForCipher),
                EncType::Rsa2048OaepSha256HmacSha256B64 => {
                    Err(CipherError::InvalidKeyTypeForCipher)
                }
                EncType::Rsa2048OaepSha1HmacSha256B64 => Err(CipherError::InvalidKeyTypeForCipher),
            },
        }
    }

    pub fn encrypt(
        content: &str,
        enc_key: &EncryptionKey,
        mac_key: &MacKey,
    ) -> Result<Self, CipherError> {
        // Only support AesCbc256HmacSHa256B64 because why not
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        type HmacSha256 = Hmac<Sha256>;
        // Generate iv of 128 bits (AES block size)
        let iv: [u8; 128 / 8] = rand::random();
        let iv = Vec::from(iv);
        let aes = Aes256CbcEnc::new_from_slices(&enc_key.0, &iv)
            .map_err(CipherError::InvalidKeyOrIvLength)?;

        let ct = aes.encrypt_padded_vec_mut::<Pkcs7>(content.as_bytes());

        let mut hmac =
            HmacSha256::new_from_slice(&mac_key.0).map_err(CipherError::InvalidKeyOrIvLength)?;
        hmac.update(&iv);
        hmac.update(&ct);
        let mac = hmac.finalize().into_bytes().as_slice().to_owned();

        Ok(Self::Value {
            enc_type: EncType::AesCbc256HmacSha256B64,
            ct,
            iv,
            mac,
        })
    }

    pub fn decrypt_to_string(&self, enc_key: &EncryptionKey, mac_key: &MacKey) -> String {
        self.decrypt(enc_key, mac_key)
            .ok()
            .and_then(|s| String::from_utf8(s).ok())
            .unwrap_or_default()
    }

    pub fn decrypt_with_private_key(
        &self,
        private_key: &DerPrivateKey,
    ) -> Result<Vec<u8>, CipherError> {
        match self {
            Self::Empty => Ok(vec![]),
            Self::Value { enc_type, .. } => match enc_type {
                EncType::Rsa2048OaepSha256B64 => self.decrypt_rsa2048_oaepsha256(private_key),
                EncType::Rsa2048OaepSha1B64 => self.decrypt_rsa2048_oaepsha1(private_key),
                EncType::Rsa2048OaepSha256HmacSha256B64 => {
                    self.decrypt_rsa2048_oaepsha256_hmacsha256(private_key)
                }
                EncType::Rsa2048OaepSha1HmacSha256B64 => {
                    self.decrypt_rsa2048_oaepsha1_hmacsha256(private_key)
                }
                EncType::AesCbc256B64 => Err(CipherError::InvalidKeyTypeForCipher),
                EncType::AesCbc128HmacSha256B64 => Err(CipherError::InvalidKeyTypeForCipher),
                EncType::AesCbc256HmacSha256B64 => Err(CipherError::InvalidKeyTypeForCipher),
            },
        }
    }

    fn decrypt_aescbc256(
        &self,
        _enc_key: &EncryptionKey,
        _mac_key: &MacKey,
    ) -> Result<Vec<u8>, CipherError> {
        unimplemented!()
    }
    fn decrypt_aescbc128_hmac_sha256(
        &self,
        _enc_key: &EncryptionKey,
        _mac_key: &MacKey,
    ) -> Result<Vec<u8>, CipherError> {
        unimplemented!()
    }
    fn decrypt_aescbc256_hmac_sha256(
        &self,
        enc_key: &EncryptionKey,
        mac_key: &MacKey,
    ) -> Result<Vec<u8>, CipherError> {
        if let Self::Value { iv, ct, mac, .. } = self {
            type Aes256CbcDec = cbc::Decryptor<Aes256>;
            type HmacSha256 = Hmac<Sha256>;

            let mut hmac = HmacSha256::new_from_slice(&mac_key.0).unwrap();
            let data = [&iv[..], &ct[..]].concat();

            hmac.update(&data);
            hmac.verify_slice(mac)
                .map_err(CipherError::MacVerificationFailed)?;

            let aes = Aes256CbcDec::new_from_slices(&enc_key.0, iv.as_slice())
                .context("Initializing AES failed")?;

            let decrypted = aes
                .decrypt_padded_vec_mut::<Pkcs7>(ct.as_slice())
                .map_err(CipherError::InvalidPadding)?;

            Ok(decrypted)
        } else {
            panic!("Tried to decrypt empty cipher")
        }
    }

    fn decrypt_rsa2048_oaepsha256(
        &self,
        _private_key: &DerPrivateKey,
    ) -> Result<Vec<u8>, CipherError> {
        unimplemented!()
    }
    fn decrypt_rsa2048_oaepsha1(
        &self,
        private_key: &DerPrivateKey,
    ) -> Result<Vec<u8>, CipherError> {
        if let Self::Value { ct, .. } = self {
            let rsa_key = RsaPrivateKey::from_pkcs8_der(&private_key.0)
                .context("Reading RSA private key failed")?;

            let padding = PaddingScheme::new_oaep::<sha1::Sha1>();
            let res = rsa_key
                .decrypt(padding, ct.as_slice())
                .context("RSA decryption failed")?;

            Ok(res)
        } else {
            panic!("Tried to decrypt empty cipher")
        }
    }
    fn decrypt_rsa2048_oaepsha256_hmacsha256(
        &self,
        _private_key: &DerPrivateKey,
    ) -> Result<Vec<u8>, CipherError> {
        unimplemented!()
    }
    fn decrypt_rsa2048_oaepsha1_hmacsha256(
        &self,
        _private_key: &DerPrivateKey,
    ) -> Result<Vec<u8>, CipherError> {
        unimplemented!()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum EncType {
    AesCbc256B64,
    AesCbc128HmacSha256B64,
    AesCbc256HmacSha256B64,
    Rsa2048OaepSha256B64,
    Rsa2048OaepSha1B64,
    Rsa2048OaepSha256HmacSha256B64,
    Rsa2048OaepSha1HmacSha256B64,
}

impl EncType {
    fn has_iv(&self) -> bool {
        self == &EncType::AesCbc256B64
            || self == &EncType::AesCbc128HmacSha256B64
            || self == &EncType::AesCbc256HmacSha256B64
    }

    fn has_mac(&self) -> bool {
        self != &EncType::AesCbc256B64
            && self != &EncType::Rsa2048OaepSha1B64
            && self != &EncType::Rsa2048OaepSha256B64
    }
}

impl FromStr for EncType {
    type Err = CipherError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "0" => Ok(EncType::AesCbc256B64),
            "1" => Ok(EncType::AesCbc128HmacSha256B64),
            "2" => Ok(EncType::AesCbc256HmacSha256B64),
            "3" => Ok(EncType::Rsa2048OaepSha256B64),
            "4" => Ok(EncType::Rsa2048OaepSha1B64),
            "5" => Ok(EncType::Rsa2048OaepSha256HmacSha256B64),
            "6" => Ok(EncType::Rsa2048OaepSha1HmacSha256B64),
            _ => Err(CipherError::UnknownCipherEncryptionType(s.to_string())),
        }
    }
}

#[test]
fn test_create_master_password_hash() {
    let key = create_master_key("foobar@example.com", "asdasdasd", 100_000);
    let pass_hash = create_master_password_hash(&key, "asdasdasd");
    assert_eq!(
        base64::encode(&pass_hash.0),
        "7jACo78yJ4rlybclGvCGjcE1bqPBXO3Gjvvg9mkFnl8="
    );
}

#[test]
fn test_create_master_key() {
    let key = create_master_key("foobar@example.com", "asdasdasd", 100_000);
    assert_eq!(
        base64::encode(&key.0),
        "WKBariwK2lofMJ27IZhzWlXvrriiH6Tht66VjxcRF7c="
    )
}

#[test]
fn test_parse_cipher() {
    let cipher_string = "2.ZgmAs5yxnEpBr7PoAnN9DA==|R8LcKh6xdKqzXm9s3yr2cw==|iAmlUJJFzPT/u7pVzyub44iwbVEpG7e9NDnwNubzV6M=";
    let cipher = Cipher::from_str(cipher_string).unwrap();

    assert!(
        matches!(cipher, Cipher::Value {enc_type, ..} if enc_type == EncType::AesCbc256HmacSha256B64)
    );
}

#[test]
fn test_decrypt_cipher() {
    let cipher_string = "2.OixUIKgN6/vWRoSvC0aTCA==|Ts7tpWXO28X2l7XSU4trsA==|q6Vz+/1QADVZRwZ1qoPoRoSvVd01A6le+nbSQxjmGDI=";
    let cipher = Cipher::from_str(cipher_string).unwrap();

    let master_key = create_master_key("foobar@example.com", "asdasdasd", 100_000);
    let enc_key = "2.BztLR8IR0LVpkRL222P4rg==|cBSzwekYt1RPgYAEHI29mtqrjRge8U+FOSmtJtheAMnaEq4eCEurazgzRweksbE9abJYxriOXFnzTR/13HyCJqO9ytLK11N+G0kmhdW/scM=|nLLHbuK4KnVJnRyVIfOu396iI7xJ/ZXWYHRscMFugTI=";

    let (dec_enc_key, dec_mac_key) =
        decrypt_symmetric_keys(&enc_key.parse().unwrap(), &master_key).unwrap();

    let res = cipher.decrypt(&dec_enc_key, &dec_mac_key).unwrap();

    let res = String::from_utf8(res).unwrap();

    assert_eq!("Test", res);
}
