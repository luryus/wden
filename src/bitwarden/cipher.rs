use aes::Aes256;
use base64;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use itertools::Itertools;
use ring::{digest, hkdf, pbkdf2};
use rsa::{PaddingScheme, RsaPrivateKey};
use rsa::pkcs8::FromPrivateKey;
use serde::de;
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::num;
use std::str::FromStr;
use std::convert::TryInto;
use thiserror::Error;
use anyhow::Context;

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

pub type MasterKey = [u8; CREDENTIAL_LEN];
pub type MasterPasswordHash = [u8; CREDENTIAL_LEN];
pub type EncryptionKey = [u8; CREDENTIAL_LEN];
pub type MacKey = [u8; CREDENTIAL_LEN];

// Private key is in DER format
pub type DerPrivateKey = Vec<u8>;

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Master key strecthing failed")]
    MasterKeyStretchFailed,
    #[error("Decrypted key length was invalid")]
    InvalidKeyLength,
    #[error("Cipher decryption failed")]
    CipherDecryptionFailed(#[from] anyhow::Error),
    #[error("Cipher string was in an invalid format")]
    InvalidCipherStringFormat,
    #[error("Unknown cipher encryption type {0}")]
    UnknownCipherEncryptionType(String),
    #[error("Invalid key type for cipher")]
    InvalidKeyTypeForCipher
}

pub fn create_master_key(
    user_email: &str,
    user_password: &str,
    hash_iterations: std::num::NonZeroU32,
) -> MasterKey {
    let mut res: MasterKey = [0u8; CREDENTIAL_LEN];

    pbkdf2::derive(
        PBKDF2_ALG,
        hash_iterations,
        user_email.as_bytes(),
        user_password.as_bytes(),
        &mut res,
    );

    res
}

pub fn create_master_password_hash(
    master_key: MasterKey,
    user_password: &str,
) -> MasterPasswordHash {
    let mut res: MasterPasswordHash = [0; CREDENTIAL_LEN];

    pbkdf2::derive(
        PBKDF2_ALG,
        num::NonZeroU32::new(1).unwrap(),
        user_password.as_bytes(),
        &master_key,
        &mut res,
    );

    res
}

pub fn decrypt_symmetric_keys(
    key_cipher: &Cipher,
    master_key: MasterKey,
) -> Result<(EncryptionKey, MacKey), CipherError> {
    let (master_enc, master_mac) = expand_master_key(master_key)
        .ok_or(CipherError::MasterKeyStretchFailed)?;

    let dec_cipher = key_cipher
        .decrypt(&master_enc, &master_mac)?;

    extract_enc_mac_keys(&dec_cipher)
}

fn extract_enc_mac_keys(full_key: &[u8]) -> Result<(EncryptionKey, MacKey), CipherError> {
    let enc_key = full_key.iter().take(32).copied().collect::<Vec<_>>();
    let mac_key = full_key.iter().skip(32).take(32).copied().collect::<Vec<_>>();

    if enc_key.len() != 32 || mac_key.len() != 32 {
        return Err(CipherError::InvalidKeyLength);
    }

    let enc_key: EncryptionKey = enc_key[..].try_into().unwrap();
    let mac_key: MacKey = mac_key[..].try_into().unwrap();

    Ok((enc_key, mac_key))
}

fn expand_master_key(master_key: MasterKey) -> Option<([u8; 32], [u8; 32])> {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &master_key);
    let enc_info = ["enc".as_bytes()];
    let mac_info = ["mac".as_bytes()];
    let enc_okm = prk.expand(&enc_info, hkdf::HKDF_SHA256).ok()?;
    let mut enc_out = [0u8; 32];
    enc_okm.fill(&mut enc_out).ok()?;

    let mac_okm = prk.expand(&mac_info, hkdf::HKDF_SHA256).ok()?;
    let mut mac_out = [0u8; 32];
    mac_okm.fill(&mut mac_out).ok()?;

    Some((enc_out, mac_out))
}

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
            .split(".")
            .collect_tuple()
            .ok_or(CipherError::InvalidCipherStringFormat)?;
        let enc_type = EncType::from_str(enc_type_str)?;

        match (enc_type.has_iv(), enc_type.has_mac()) {
            (true, true) => {
                let (iv_b64, ct_b64, mac_b64) = rest
                .split("|")
                .collect_tuple()
                .ok_or(CipherError::InvalidCipherStringFormat)?;
    
                let iv = base64::decode(iv_b64).or(Err(CipherError::InvalidCipherStringFormat))?;
                let ct = base64::decode(ct_b64).or(Err(CipherError::InvalidCipherStringFormat))?;
                let mac = base64::decode(mac_b64).or(Err(CipherError::InvalidCipherStringFormat))?;
    
                Ok(Cipher::Value {
                    enc_type,
                    iv,
                    ct,
                    mac,
                })
            },
            (false, false) => {
                let iv = vec![];
                let mac = vec![];
                let ct = base64::decode(rest).or(Err(CipherError::InvalidCipherStringFormat))?;
                Ok(Cipher::Value {
                    enc_type, iv, ct, mac
                })
            },
            _ => unimplemented!()
        }
    
    }
}

impl Cipher {
    pub fn decrypt(&self, enc_key: &EncryptionKey, mac_key: &MacKey) -> Result<Vec<u8>, CipherError> {
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
                EncType::Rsa2048OaepSha1HmacSha256B64 => {
                    Err(CipherError::InvalidKeyTypeForCipher)
                }
            },
        }
    }

    pub fn decrypt_to_string(&self, enc_key: &EncryptionKey, mac_key: &MacKey) -> String {
        self.decrypt(enc_key, mac_key)
            .ok()
            .and_then(|s| String::from_utf8(s).ok())
            .unwrap_or(String::new())
    }

    pub fn decrypt_with_private_key(&self, private_key: &DerPrivateKey) -> Result<Vec<u8>, CipherError> {
        match self {
            Self::Empty => Ok(vec![]),
            Self::Value { enc_type, .. } => match enc_type {
                EncType::Rsa2048OaepSha256B64 => self.decrypt_rsa2048_oaepsha256(private_key),
                EncType::Rsa2048OaepSha1B64 => self.decrypt_rsa2048_oaepsha1(private_key),
                EncType::Rsa2048OaepSha256HmacSha256B64 => self.decrypt_rsa2048_oaepsha256_hmacsha256(private_key),
                EncType::Rsa2048OaepSha1HmacSha256B64 => self.decrypt_rsa2048_oaepsha1_hmacsha256(private_key),
                EncType::AesCbc256B64 => Err(CipherError::InvalidKeyTypeForCipher),
                EncType::AesCbc128HmacSha256B64 => Err(CipherError::InvalidKeyTypeForCipher),
                EncType::AesCbc256HmacSha256B64 => {
                    Err(CipherError::InvalidKeyTypeForCipher)
                }
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
            type Aes256Cbc = Cbc<Aes256, Pkcs7>;

            let mac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, mac_key);
            let data = [&iv[..], &ct[..]].concat();
            ring::hmac::verify(&mac_key, &data, &mac)
                .or(Err(anyhow::anyhow!("Hmac verification failed")))?;

            let aes = Aes256Cbc::new_var(enc_key, iv.as_slice())
                .context("Initializing AES failed")?;

            let decrypted = aes.decrypt_vec(ct.as_slice())
                .context("Aes decryption failed")?;

            Ok(decrypted)
        } else {
            panic!("Tried to decrypt empty cipher")
        }
    }

    fn decrypt_rsa2048_oaepsha256(
        &self,
        _private_key: &DerPrivateKey
    ) -> Result<Vec<u8>, CipherError> {
        unimplemented!()
    }
    fn decrypt_rsa2048_oaepsha1(
        &self,
        private_key: &DerPrivateKey
    ) -> Result<Vec<u8>, CipherError> {
        if let Self::Value { ct, .. } = self {
            let rsa_key = RsaPrivateKey::from_pkcs8_der(&private_key)
                .context("Reading RSA private key failed")?;
    
            let padding = PaddingScheme::new_oaep::<sha1::Sha1>();
            let res = rsa_key.decrypt(padding, ct.as_slice())
                .context("RSA decryption failed")?;
    
            Ok(res)
        } else {
            panic!("Tried to decrypt empty cipher")
        }
    }
    fn decrypt_rsa2048_oaepsha256_hmacsha256(
        &self,
        _private_key: &DerPrivateKey
    ) -> Result<Vec<u8>, CipherError> {
        unimplemented!()
    }
    fn decrypt_rsa2048_oaepsha1_hmacsha256(
        &self,
        _private_key: &DerPrivateKey
    ) -> Result<Vec<u8>, CipherError> {
        unimplemented!()
    }
}

#[derive(Debug, PartialEq)]
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
        self == &EncType::AesCbc256B64 || self == &EncType::AesCbc128HmacSha256B64 || self == &EncType::AesCbc256HmacSha256B64
    }

    fn has_mac(&self) -> bool {
        self != &EncType::AesCbc256B64 &&
        self != &EncType::Rsa2048OaepSha1B64 &&
        self != &EncType::Rsa2048OaepSha256B64
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
    let key = create_master_key(
        "foobar@example.com",
        "asdasdasd",
        num::NonZeroU32::new(100000).unwrap(),
    );
    let pass_hash = create_master_password_hash(key, "asdasdasd");
    assert_eq!(
        base64::encode(&pass_hash),
        "7jACo78yJ4rlybclGvCGjcE1bqPBXO3Gjvvg9mkFnl8="
    );
}

#[test]
fn test_create_master_key() {
    let key = create_master_key(
        "foobar@example.com",
        "asdasdasd",
        num::NonZeroU32::new(100000).unwrap(),
    );
    assert_eq!(
        base64::encode(&key),
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

    let master_key = create_master_key(
        "foobar@example.com",
        "asdasdasd",
        num::NonZeroU32::new(100000).unwrap(),
    );
    let enc_key = "2.BztLR8IR0LVpkRL222P4rg==|cBSzwekYt1RPgYAEHI29mtqrjRge8U+FOSmtJtheAMnaEq4eCEurazgzRweksbE9abJYxriOXFnzTR/13HyCJqO9ytLK11N+G0kmhdW/scM=|nLLHbuK4KnVJnRyVIfOu396iI7xJ/ZXWYHRscMFugTI=";

    let (dec_enc_key, dec_mac_key) =
        decrypt_symmetric_keys(&enc_key.parse().unwrap(), master_key).unwrap();

    let res = cipher.decrypt(&dec_enc_key, &dec_mac_key).unwrap();

    let res = String::from_utf8(res).unwrap();

    assert_eq!("Test", res);
}
