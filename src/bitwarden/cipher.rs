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
use std::fmt;

use std::pin::Pin;
use std::str::FromStr;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const CREDENTIAL_LEN: usize = 256 / 8;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterKey(Pin<Box<[u8; CREDENTIAL_LEN]>>);
impl MasterKey {
    fn new() -> Self {
        MasterKey(Box::pin([0; CREDENTIAL_LEN]))
    }

    #[cfg(test)]
    fn from_base64(b64_data: &str) -> Result<Self, base64::DecodeError> {
        let mut key = Self::new();
        let len = base64::decode_config_slice(
            b64_data, base64::STANDARD, key.0.as_mut_slice())?;
        if len == key.0.len() {
            Ok(key)   
        } else {
            Err(base64::DecodeError::InvalidLength)
        }
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MasterPasswordHash(Pin<Box<[u8; CREDENTIAL_LEN]>>);
impl MasterPasswordHash {
    fn new() -> Self {
        MasterPasswordHash(Box::pin([0; CREDENTIAL_LEN]))
    }

    pub fn base64_encoded(&self) -> Zeroizing<String> {
        base64::encode(self.0.as_slice()).into()
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct EncryptionKey(Pin<Box<[u8; CREDENTIAL_LEN]>>);
impl EncryptionKey {
    fn new() -> Self {
        Self(Box::pin([0u8; CREDENTIAL_LEN]))
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MacKey(Pin<Box<[u8; CREDENTIAL_LEN]>>);
impl MacKey {
    fn new() -> Self {
        Self(Box::pin([0u8; CREDENTIAL_LEN]))
    }
}

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
        res.0.as_mut_slice(),
    );
    res
}

pub fn create_master_password_hash(
    master_key: &MasterKey,
    user_password: &str,
) -> MasterPasswordHash {
    let mut res = MasterPasswordHash::new();
    pbkdf2::pbkdf2::<Hmac<Sha256>>(
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
) -> Result<(EncryptionKey, MacKey), CipherError> {
    let (master_enc, master_mac) = expand_master_key(master_key);
    let dec_cipher = key_cipher.decrypt(&master_enc, &master_mac)?;

    extract_enc_mac_keys(&dec_cipher)
}

pub fn extract_enc_mac_keys(full_key: &[u8]) -> Result<(EncryptionKey, MacKey), CipherError> {
    // Enc key and mac key should both be 32 byets
    if full_key.len() != 2 * 32 {
        return Err(CipherError::InvalidKeyLength);
    }

    let mut enc_key = EncryptionKey::new();
    let mut mac_key = MacKey::new();

    enc_key.0.as_mut_slice().copy_from_slice(&full_key[..32]);
    mac_key.0.as_mut_slice().copy_from_slice(&full_key[32..]);

    Ok((enc_key, mac_key))
}

fn expand_master_key(master_key: &MasterKey) -> (EncryptionKey, MacKey) {
    type HkdfSha256 = Hkdf<Sha256>;

    let prk = HkdfSha256::from_prk(master_key.0.as_slice()).unwrap();

    let enc_info = "enc".as_bytes();
    let mac_info = "mac".as_bytes();

    let mut enc_key = EncryptionKey::new();
    prk.expand(enc_info, enc_key.0.as_mut_slice()).unwrap();
    let mut mac_key = MacKey::new();
    prk.expand(mac_info, mac_key.0.as_mut_slice()).unwrap();

    (enc_key, mac_key)
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
        content: &[u8],
        enc_key: &EncryptionKey,
        mac_key: &MacKey,
    ) -> Result<Self, CipherError> {
        // Only support AesCbc256HmacSHa256B64 because why not
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        type HmacSha256 = Hmac<Sha256>;
        // Generate iv of 128 bits (AES block size)
        let iv: [u8; 128 / 8] = rand::random();
        let iv = Vec::from(iv);
        let aes = Aes256CbcEnc::new_from_slices(enc_key.0.as_slice(), &iv)
            .map_err(CipherError::InvalidKeyOrIvLength)?;

        let ct = aes.encrypt_padded_vec_mut::<Pkcs7>(content);

        let mut hmac = HmacSha256::new_from_slice(mac_key.0.as_slice())
            .map_err(CipherError::InvalidKeyOrIvLength)?;
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

            let mut hmac = HmacSha256::new_from_slice(mac_key.0.as_slice()).unwrap();
            let data = [&iv[..], &ct[..]].concat();

            hmac.update(&data);
            hmac.verify_slice(mac)
                .map_err(CipherError::MacVerificationFailed)?;

            let aes = Aes256CbcDec::new_from_slices(enc_key.0.as_slice(), iv.as_slice())
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

    pub fn encode(&self) -> String {
        match self {
            Cipher::Empty => String::new(),
            Cipher::Value { enc_type, iv, ct, mac } => {
                let b64_ct = base64::encode(&ct);
                match (enc_type.has_mac(), enc_type.has_iv()) {
                    (true, true) => {
                        let b64_iv = base64::encode(&iv);
                        let b64_mac = base64::encode(&mac);
                        format!("{}.{}|{}|{}",
                            *enc_type as u8,
                            b64_iv, b64_ct, b64_mac)
                    }
                    (false, false) => format!("{}.{}", *enc_type as u8, b64_ct),
                    _ => unimplemented!()
                }
            },
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EncType {
    AesCbc256B64 = 0,
    AesCbc128HmacSha256B64 = 1,
    AesCbc256HmacSha256B64 = 2,
    Rsa2048OaepSha256B64 = 3,
    Rsa2048OaepSha1B64 = 4,
    Rsa2048OaepSha256HmacSha256B64 = 5,
    Rsa2048OaepSha1HmacSha256B64 = 6,
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

#[cfg(test)]
mod tests {
    use super::*;

    mod testdata {
        pub const USER_EMAIL: &str = "foobar@example.com";
        pub const USER_PASSWORD: &str = "asdasdasd";
        pub const USER_HASH_ITERATIONS: u32 = 100_000;

        pub const USER_MASTER_KEY_B64: &str = "WKBariwK2lofMJ27IZhzWlXvrriiH6Tht66VjxcRF7c=";
        pub const USER_MASTER_PASSWORD_HASH_B64: &str =
            "7jACo78yJ4rlybclGvCGjcE1bqPBXO3Gjvvg9mkFnl8=";

        // Contains the encryption key of the user encrypted
        // with the master key
        pub const USER_SYMMETRIC_KEY_CIPHER_STRING: &str = 
            "2.BztLR8IR0LVpkRL222P4rg==\
             |cBSzwekYt1RPgYAEHI29mtqrjRge8U+FOSmtJtheAMnaEq4eCEurazgzRweksbE9abJYxriOXFnzTR/13HyCJqO9ytLK11N+G0kmhdW/scM=\
             |nLLHbuK4KnVJnRyVIfOu396iI7xJ/ZXWYHRscMFugTI=";

        // Contains the (asymmetric) private key of the user,
        // encrypted with the symmetric key
        pub const USER_PRIVATE_KEY_CIPHER_STRING: &str =
            "2.G+7HwPaG5oG6GqQAC1ANsA==|wH37HJOmlJ3N1BUo9sncrcoHRCKR6hJnCDyKOKvd1TfzRWu5uNLtzYmd33m\
            G155jYTX6Sa+HD83eGRoWzjlZxPeX40nHVFEsLbqAyNgpMfLahtF4mM2fcaTLuPpOQxY+tNdFaU8lgjH42eYAkR\
            R0aPjUaX9WYWZoJvFFz/4bQjMM9kmKIC6kuhHerDZq/hr+6TwMJXLz7Y+NXvP5ESdU8D1INaDBqlny5K1VtvvLj\
            3hdVuBM6J1NaDPcrUBjGq9tBLa1fpc0r3HUHpRojWEfKUbwXE1w0DcCb/7XiVdSK0GUxhEJrjrdKoSjih5usXQ3\
            lgj6sj2x/OA2zcHIpI1p5ATmbgEWtTsYPyBH+JxdIVL8IDuE2v3IcTIDDAsPIbYKy2Lzr/+GDAginVs3FH16o80\
            e3lJf1r6Nj1szXgC617fNtrrU+hmZXk4vf0+YRr6GBIcfWk0pFV9Emf7cMiPGzopIK7OQLBME0xdQ2h3lMPQu6r\
            PUbNmt4OWmDjUJ/1fqDhPZN0oJT6KLm7V/jdF8a0pnO7mm4WXc3/drekOEwugG7MAwzXfWohtnP0mceMNf7K2vF\
            NbZGu4CfiICXVXszrHkusKCz/oa6aDUbX9XHYnzl5nulavp0TGI5CMPx5ryImIoXeYO9REdTT116iU0AR97e9ci\
            mnMXcdj+s4vmYzvCDTuSFOsZ5VKFSAjzXJRbFErPBW6WO3P38IZWnviDUEgg9gPgJk64iX2+0XVUXppvpbe9OSq\
            QTS5wOSRg1zQIabY7G7L7Oc6ohi9l8Av0f8OkS+nVqpJhSFiH/DPqsXKyswN17mcdVK1NBN9E5lHr++y6lfpopn\
            Uou9Ub4LPUkshaFo3MK8mqvqIFl2h0Uo5JwGE51f2fJL/s4mLKMC2jmRbd83FCTmttrcCgRJJyuctbqN1G5HTCi\
            jgi6B9Asj4UoQrhJPq8pAYgqdXpCTXHYn/8gXXVmzc8QrPIJAUfe6EsxZuL7IdjhgS0LUv16b1E0DqyXT6/3ipf\
            LOjK/ay6VoUrTRuku9APdc4NGwLhNQLbmdscBBDlfd/3rgbv1f3StkSMtNDGTp6Bk+6MppjCKF1jcKE/HKhi8/q\
            pgb+P5yN8P+g6QH/YmUVjYW8BQqvVraYoRVvrZZ5dJDGgdIlv15R0Lv/CvCtfRl9edcOZ9MDbHYcTtGYL+hIajs\
            qMurJwadlQ6V9zY48V7SUyCbVFaW4ZqHsZeg2TqmhqJb8hvYjER8Jd7A1jdO6JuQCQI6TiZb+bXpomEOud3k6n2\
            1Hcttk6N8uYXTX93Tf62tu4mnBqBq5FHJoaz0E4qYUmfKjhWXn2e7k4e0SGDx6wp/wr4mn/R6xGM3gI32puuUSD\
            l5h0trrlIAbW0uGI8FWQKSskw7N+SOSTs7eYvQBrHKaaOtL6OPxBiahLtay48uR3CPBpstw1pSL6QSi9RnL1j42\
            BKpr7YwlyXTceQ/0V0PTfsWBYg85nBG21qwvTHPMim2XRibnIsW5YQhxzUBQ/JDNOvsuVc3HTGvaXza0VRXWJ0S\
            Yo0XZpjrQbGw6eICpXcUreZVecO5uoHh1WC1za2TY1IZ38IqwhZ8ZBjaN67H0GaTNqVjDaa46RoticfyDs0SJSW\
            gssTLUwJts7RSd1+lQ=|rFzZYOkVQOu5mEWWDfvPpLrdIrOoOy8rmJfbJUjPV94=";
            
        // Contains the string "Test", encrypted with the public key of the user 
        pub const TEST_CIPHER_STRING_ASYMMETRIC: &str =
            "4.CzrGfIA+mHbPJy9km5J+gsC4mgwvu5267Xk2kfBscqroqEFza6g2a+fkRcaoXOIX+1Pq7DcwlbgQ\
             6GVMMwA8Orm4uA4v8XCGH2Zsj3wVVnloNxsVYDmny6HFWMuJdfbNUXO/jdIjF8R8hzPka2hQ5jAZ\
             3d81ivaQ+EqC9uKU+UOudAx9oPoD3F12DgVZJxKrbL+yi9Z8rD4ospic9ntuUfOUEesRD/q/g9yT\
             aKWwdPnegyIfId9cB4PhUZhMx02kDildno4VOGu6iTpLmeRZPi2RY3YN9tCDzYnxbK1Nf41zzQYR\
             bUPunAoQPCIv8Akpq0hEfUhciN3pqMSVtqUiKA==";

        // Contains the string "Test" encrypted with the key of the
        // testdata user
        pub const TEST_CIPHER_STRING: &str = 
            "2.OixUIKgN6/vWRoSvC0aTCA==\
             |Ts7tpWXO28X2l7XSU4trsA==\
             |q6Vz+/1QADVZRwZ1qoPoRoSvVd01A6le+nbSQxjmGDI=";
    }

    #[test]
    fn test_create_master_password_hash() {
        let master_key = MasterKey::from_base64(testdata::USER_MASTER_KEY_B64)
            .expect("Master key decoding failed");
        let pass_hash = create_master_password_hash(&master_key, testdata::USER_PASSWORD);
        assert_eq!(
            base64::encode(pass_hash.0.as_slice()),
            testdata::USER_MASTER_PASSWORD_HASH_B64
        );
    }

    #[test]
    fn test_create_master_key() {
        let key = create_master_key(
            testdata::USER_EMAIL,
            testdata::USER_PASSWORD,
            testdata::USER_HASH_ITERATIONS
        );
        assert_eq!(
            base64::encode(key.0.as_slice()),
            testdata::USER_MASTER_KEY_B64
        );
    }

    #[test]
    fn test_parse_cipher() {
        let cipher = Cipher::from_str(testdata::TEST_CIPHER_STRING).unwrap();

        assert!(
            matches!(cipher, Cipher::Value {enc_type, ..} if enc_type == EncType::AesCbc256HmacSha256B64)
        );
    }

    #[test]
    fn test_decrypt_cipher_with_user_symmetric_key() {
        let cipher = Cipher::from_str(testdata::TEST_CIPHER_STRING).unwrap();

        let master_key = MasterKey::from_base64(testdata::USER_MASTER_KEY_B64)
            .expect("Master key decoding failed");
        let enc_key = testdata::USER_SYMMETRIC_KEY_CIPHER_STRING.parse()
            .expect("Parsing symmetric key Cipher failed");

        let (dec_enc_key, dec_mac_key) = decrypt_symmetric_keys(&enc_key, &master_key).unwrap();

        let res = cipher.decrypt(&dec_enc_key, &dec_mac_key).unwrap();

        let res = String::from_utf8(res).unwrap();

        assert_eq!("Test", res);
    }

    #[test]
    fn test_decrypt_cipher_with_private_key() {
        let master_key = MasterKey::from_base64(testdata::USER_MASTER_KEY_B64)
            .expect("Master key decoding failed");
        let enc_key = testdata::USER_SYMMETRIC_KEY_CIPHER_STRING.parse()
            .expect("Parsing symmetric key Cipher failed");
        let (dec_enc_key, dec_mac_key) = decrypt_symmetric_keys(&enc_key, &master_key).unwrap();

        let der_private_key: DerPrivateKey = testdata::USER_PRIVATE_KEY_CIPHER_STRING
            .parse::<Cipher>().unwrap()
            .decrypt(&dec_enc_key, &dec_mac_key).unwrap()
            .into();
        
        let test_cipher = Cipher::from_str(testdata::TEST_CIPHER_STRING_ASYMMETRIC).unwrap();
        let res = test_cipher.decrypt_with_private_key(&der_private_key).unwrap();
        let res = String::from_utf8(res).unwrap();

        assert_eq!("Test", res);
    }
}
