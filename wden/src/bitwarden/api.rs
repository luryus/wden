use super::apikey::ApiKey;
use super::cipher::{Cipher, KeyDerivationFunction, PbkdfParameters};
use super::server::ServerConfiguration;
use anyhow::{bail, Error};
use base64::prelude::*;
use reqwest;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_repr::Deserialize_repr;
use std::convert::TryInto;
use std::time::{Duration, Instant};
use std::{collections::HashMap, convert::TryFrom};

const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[allow(clippy::enum_variant_names)]
enum DeviceType {
    WindowsCLI = 23,
    MacOsCLI = 24,
    LinuxCLI = 25,
}

const fn get_device_type() -> DeviceType {
    if cfg!(windows) {
        DeviceType::WindowsCLI
    } else if cfg!(target_os = "macos") {
        DeviceType::MacOsCLI
    } else {
        DeviceType::LinuxCLI
    }
}

const fn get_device_name() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

pub struct ApiClient {
    http_client: reqwest::Client,
    api_base_url: Url,
    identity_base_url: Url,
    device_identifier: String,
    access_token: Option<String>,
}

impl ApiClient {
    pub fn new(
        server_config: &ServerConfiguration,
        device_identifier: impl Into<String>,
        accept_invalid_certs: bool,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .user_agent(APP_USER_AGENT)
            .danger_accept_invalid_certs(accept_invalid_certs)
            .build()
            .unwrap();
        ApiClient {
            http_client,
            api_base_url: server_config.api_base_url(),
            identity_base_url: server_config.identity_base_url(),
            device_identifier: device_identifier.into(),
            access_token: None,
        }
    }

    pub fn with_token(
        server_config: &ServerConfiguration,
        device_identifier: impl Into<String>,
        token: &str,
        accept_invalid_certs: bool,
    ) -> Self {
        let mut c = Self::new(server_config, device_identifier, accept_invalid_certs);
        c.access_token = Some(token.to_string());
        c
    }

    pub async fn prelogin(&self, user_email: &str) -> Result<PbkdfParameters, Error> {
        let mut body = HashMap::new();
        body.insert("email", user_email);

        let url = self.identity_base_url.join("accounts/prelogin")?;

        let res = self
            .http_client
            .post(url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        let res: PreloginResponse = res.json().await?;
        Ok(res.into())
    }

    /// Make Bitwarden (OAuth) /identity/token api call for authenticating.
    ///
    /// Arguments:
    /// * `username`: User's username. Most often this is the user email.
    /// * `password`: User's master password hash. Not the actual password.
    /// * `two_factor`: Optional tuple describing the second factor type, the second factor token and
    ///                 whether to token should be "remembered" by the server or not. None if two-factor
    ///                 is not used.
    /// * `captcha_token`: Token for skipping the captcha check. Either the user's private api key or a captcha
    ///                    bypass token sent by the server.
    pub async fn get_token(
        &self,
        username: &str,
        password: &str,
        two_factor: Option<(TwoFactorProviderType, &str, bool)>,
        captcha_token: Option<&str>,
    ) -> Result<TokenResponse, Error> {
        let device_type = (get_device_type() as i8).to_string();
        let mut body = HashMap::new();
        body.insert("grant_type", "password");
        body.insert("username", username);
        body.insert("password", password);
        body.insert("scope", "api offline_access");
        body.insert("client_id", "cli");
        body.insert("deviceName", get_device_name());
        body.insert("deviceIdentifier", &self.device_identifier);
        body.insert("deviceType", &device_type);

        let two_factor_type_str;

        if let Some((two_factor_type, two_factor_token, two_factor_remember)) = two_factor {
            body.insert("twoFactorToken", two_factor_token);
            two_factor_type_str = (two_factor_type as u8).to_string();
            body.insert("twoFactorProvider", &two_factor_type_str);

            if two_factor_remember && two_factor_type != TwoFactorProviderType::Remember {
                body.insert("twoFactorRemember", "1");
            }
        }

        if let Some(ct) = captcha_token {
            body.insert("captchaResponse", ct);
        }

        let url = self.identity_base_url.join("connect/token")?;

        let res = self
            .http_client
            .post(url)
            .form(&body)
            // As of October 2021, Bitwarden (prod) wants the email as base64-encoded in a header
            // for some security reason
            .header("auth-email", BASE64_URL_SAFE.encode(username))
            .header("device-type", &device_type)
            // As of Nov 2024, Bitwarden wants these Bitwarden-Client- headers as well, with valid values
            .header("Bitwarden-Client-Name", "cli")
            .header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"))
            .send()
            .await?;

        if res.status() == 400 {
            log::info!("{:?}", &res);
            let body = res.json::<HashMap<String, serde_json::Value>>().await?;
            if body.contains_key("TwoFactorProviders") {
                let providers = body
                    .get("TwoFactorProviders")
                    .and_then(|ps| ps.as_array())
                    .map(|ps| {
                        ps.iter()
                            .filter_map(|p| {
                                p.as_u64()
                                    .and_then(|x| (x as u8).try_into().ok())
                                    .or_else(|| p.as_str().and_then(|x| x.try_into().ok()))
                            })
                            .collect()
                    })
                    .ok_or_else(|| anyhow::anyhow!("Error parsing provider types"))?;

                let captcha_bypass = body
                    .get("CaptchaBypassToken")
                    .and_then(|cbt| cbt.as_str())
                    .map(|s| s.to_string());

                return Ok(TokenResponse::TwoFactorRequired(providers, captcha_bypass));
            } else if body.contains_key("HCaptcha_SiteKey") {
                return Ok(TokenResponse::CaptchaRequired);
            } else {
                // The error models often include the error message,
                // so try to get and show it.
                let server_error_message = body
                    .get("ErrorModel")
                    .and_then(|em| em.as_object())
                    .and_then(|em| em.get("Message"))
                    .and_then(|m| m.as_str());

                return match server_error_message {
                    Some(msg) => Err(anyhow::anyhow!("{}", msg)),
                    None => Err(anyhow::anyhow!("Error logging in: {:?}", body)),
                };
            }
        }

        let res = res
            .error_for_status()
            .inspect_err(|e| log::warn!("Error in token request: {e}"))?
            .json::<TokenResponseSuccess>()
            .await?;

        Ok(TokenResponse::Success(Box::new(res)))
    }

    pub async fn get_token_with_api_key(
        &self,
        api_key: &ApiKey,
    ) -> Result<TokenResponseSuccess, Error> {
        let device_type = (get_device_type() as i8).to_string();
        let mut body = HashMap::new();
        body.insert("grant_type", "client_credentials");
        body.insert("username", &api_key.email);
        body.insert("client_id", &api_key.client_id);
        body.insert("client_secret", &api_key.client_secret);
        body.insert("scope", "api");
        body.insert("deviceName", get_device_name());
        body.insert("deviceIdentifier", &self.device_identifier);
        body.insert("deviceType", &device_type);

        let url = self.identity_base_url.join("connect/token")?;

        let res = self
            .http_client
            .post(url)
            .form(&body)
            // As of October 2021, Bitwarden (prod) wants the email as base64-encoded in a header
            // for some security reason
            .header("auth-email", BASE64_URL_SAFE.encode(&api_key.email))
            .header("device-type", &device_type)
            // As of May 2024, Bitwarden wants these Bitwarden-Client- headers as well
            .header("Bitwarden-Client-Name", "cli")
            .header("Bitwarden-Client-Version", env!("CARGO_PKG_VERSION"))
            .send()
            .await?;

        if res.status() == 400 {
            log::info!("{:?}", &res);
            let body = res.json::<HashMap<String, serde_json::Value>>().await?;
            // The error models often include the error message,
            // so try to get and show it.
            let server_error_message = body
                .get("ErrorModel")
                .and_then(|em| em.as_object())
                .and_then(|em| em.get("Message"))
                .and_then(|m| m.as_str());

            return match server_error_message {
                Some(msg) => Err(anyhow::anyhow!("{}", msg)),
                None => Err(anyhow::anyhow!("Error logging in: {:?}", body)),
            };
        }

        let res = res
            .error_for_status()
            .inspect_err(|e| log::warn!("Error in token request: {e}"))?
            .json::<TokenResponseSuccess>()
            .await?;

        Ok(res)
    }

    pub async fn refresh_token(
        &self,
        token: &TokenResponseSuccess,
        api_key: Option<&ApiKey>,
    ) -> Result<TokenResponse, Error> {
        if let Some(ak) = api_key {
            let res = self.get_token_with_api_key(ak).await?;
            return Ok(TokenResponse::Success(Box::new(res)));
        }

        let mut body = HashMap::new();
        if let Some(rt) = token.refresh_token.as_ref() {
            body.insert("grant_type", "refresh_token");
            body.insert("refresh_token", rt);
            body.insert("client_id", "cli");
        } else {
            bail!("Refresh token or api key not present while trying to refresh");
        }

        let url = self.identity_base_url.join("connect/token")?;

        let res = self.http_client.post(url).form(&body).send().await?;

        let refresh_res = res
            .error_for_status()?
            .json::<TokenResponseSuccess>()
            .await?;

        // The token refresh response does not include all the
        // fields. Take the old token and replace the new fields.
        let mut res = token.clone();
        res.access_token = refresh_res.access_token;
        res.refresh_token = refresh_res.refresh_token;
        res.token_timestamp = refresh_res.token_timestamp;
        res.expires_in = refresh_res.expires_in;

        Ok(TokenResponse::Success(Box::new(res)))
    }

    pub async fn sync(&self) -> Result<SyncResponse, Error> {
        assert!(self.access_token.is_some());
        let mut url = self.api_base_url.join("sync")?;
        url.set_query(Some("excludeDomains=true"));
        let res = self
            .http_client
            .get(url)
            .bearer_auth(self.access_token.as_ref().unwrap())
            .send()
            .await?
            .error_for_status()?
            .json::<SyncResponseInternal>()
            .await?
            .into();

        Ok(res)
    }
}

pub enum TokenResponse {
    Success(Box<TokenResponseSuccess>),
    TwoFactorRequired(Vec<TwoFactorProviderType>, Option<String>),
    CaptchaRequired,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TokenResponseSuccess {
    #[serde(alias = "Key")]
    pub key: Cipher,
    #[serde(alias = "PrivateKey")]
    #[serde(alias = "privateKey")]
    pub private_key: Cipher,
    pub access_token: String,
    expires_in: u32,
    pub refresh_token: Option<String>,
    #[serde(alias = "TwoFactorToken")]
    #[serde(alias = "twoFactorToken")]
    pub two_factor_token: Option<String>,
    #[serde(skip, default = "token_response_timestamp")]
    token_timestamp: Instant,

    #[serde(default, flatten)]
    // When authenticating with an API key, the token response also contains the Pbkdf parameters
    kdf_parameters: Option<PreloginResponse>,
}

impl TokenResponseSuccess {
    pub fn time_to_expiry(&self) -> Option<Duration> {
        let expires_at = self.token_timestamp + Duration::from_secs(self.expires_in as u64);
        expires_at.checked_duration_since(Instant::now())
    }

    pub fn should_refresh(&self) -> bool {
        match self.time_to_expiry() {
            None => true,
            Some(d) if d < Duration::from_secs(60 * 4) => true,
            _ => false,
        }
    }

    pub fn pbkdf_parameters(&self) -> Option<PbkdfParameters> {
        self.kdf_parameters.as_ref().map(|x| x.clone().into())
    }
}

fn token_response_timestamp() -> Instant {
    Instant::now()
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum TwoFactorProviderType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2F = 4,
    Remember = 5,
    OrganizationDuo = 6,
}

impl TryFrom<u8> for TwoFactorProviderType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == TwoFactorProviderType::Authenticator as u8 => {
                Ok(TwoFactorProviderType::Authenticator)
            }
            x if x == TwoFactorProviderType::Email as u8 => Ok(TwoFactorProviderType::Email),
            x if x == TwoFactorProviderType::Duo as u8 => Ok(TwoFactorProviderType::Duo),
            x if x == TwoFactorProviderType::YubiKey as u8 => Ok(TwoFactorProviderType::YubiKey),
            x if x == TwoFactorProviderType::U2F as u8 => Ok(TwoFactorProviderType::U2F),
            x if x == TwoFactorProviderType::Remember as u8 => Ok(TwoFactorProviderType::Remember),
            x if x == TwoFactorProviderType::OrganizationDuo as u8 => {
                Ok(TwoFactorProviderType::OrganizationDuo)
            }
            _ => Err(()),
        }
    }
}

impl TryFrom<&str> for TwoFactorProviderType {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.parse::<u8>() {
            Ok(n) => n.try_into(),
            _ => Err(()),
        }
    }
}

#[derive(Deserialize_repr, Debug, Clone, Default)]
#[repr(u8)]
enum KdfFunction {
    #[default]
    Pbkdf2 = 0,
    Argon2id = 1,
}

impl From<KdfFunction> for KeyDerivationFunction {
    fn from(kdf_function: KdfFunction) -> Self {
        match kdf_function {
            KdfFunction::Pbkdf2 => Self::Pbkdf2,
            KdfFunction::Argon2id => Self::Argon2id,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
struct PreloginResponse {
    #[serde(alias = "kdf", default)]
    #[serde(alias = "Kdf")]
    pub kdf: KdfFunction,
    #[serde(alias = "kdfIterations")]
    #[serde(alias = "KdfIterations")]
    pub kdf_iterations: u32,
    #[serde(alias = "kdfMemory")]
    #[serde(alias = "KdfMemory")]
    pub kdf_memory_mib: Option<u32>,
    #[serde(alias = "kdfParallelism")]
    #[serde(alias = "KdfParallelism")]
    pub kdf_parallelism: Option<u32>,
}

impl From<PreloginResponse> for PbkdfParameters {
    fn from(val: PreloginResponse) -> Self {
        PbkdfParameters {
            kdf: val.kdf.into(),
            iterations: val.kdf_iterations,
            memory_mib: val.kdf_memory_mib.unwrap_or_default(),
            parallelism: val.kdf_parallelism.unwrap_or_default(),
        }
    }
}

#[derive(Deserialize, Debug)]
struct SyncResponseInternal {
    #[serde(alias = "Ciphers")]
    ciphers: Vec<CipherItemInternal>,
    #[serde(alias = "Profile")]
    profile: Profile,
    #[serde(alias = "Collections")]
    collections: Vec<Collection>,
}

#[derive(Deserialize, Debug)]
pub struct Collection {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(alias = "organizationId")]
    #[serde(alias = "OrganizationId")]
    pub organization_id: String,
    #[serde(alias = "Name")]
    pub name: Cipher,
}

#[derive(Deserialize, Debug)]
pub struct Profile {
    #[serde(alias = "Organizations")]
    pub organizations: Vec<Organization>,
}

#[derive(Deserialize, Debug)]
pub struct Organization {
    #[serde(alias = "Enabled")]
    pub enabled: bool,
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(default)]
    #[serde(alias = "Key")]
    pub key: Cipher,
    #[serde(alias = "Name")]
    pub name: String,
}

pub struct SyncResponse {
    pub ciphers: Vec<CipherItem>,
    pub profile: Profile,
    pub collections: Vec<Collection>,
}

impl From<SyncResponseInternal> for SyncResponse {
    fn from(sri: SyncResponseInternal) -> Self {
        SyncResponse {
            ciphers: sri.ciphers.into_iter().map(|cii| cii.into()).collect(),
            profile: sri.profile,
            collections: sri.collections,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all="camelCase")]
pub struct CipherItemInternal {
    #[serde(alias = "Id")]
    id: String,
    #[serde(alias = "Type")]
    #[serde(alias = "type")]
    cipher_type: i32,
    #[serde(default)]
    #[serde(alias = "Name")]
    name: Cipher,
    #[serde(default)]
    #[serde(alias = "Notes")]
    notes: Cipher,
    #[serde(alias = "Login")]
    login: Option<LoginItem>,
    #[serde(alias = "Card")]
    card: Option<CardItem>,
    #[serde(alias = "Identity")]
    identity: Option<IdentityItem>,
    #[serde(alias = "secureNote")]
    #[serde(alias = "SecureNote")]
    secure_note: Option<SecureNoteItem>,
    #[serde(alias = "Favorite")]
    favorite: bool,
    #[serde(alias = "CollectionIds")]
    #[serde(alias = "collectionIds")]
    collection_ids: Vec<String>,
    #[serde(alias = "organizationId")]
    #[serde(alias = "OrganizationId")]
    organization_id: Option<String>,
    #[serde(alias = "Key")]
    key: Option<Cipher>,
    #[serde(alias = "lastKnownRevisionDate")]
    #[serde(alias = "LastKnownRevisionDate")]
    last_known_revision_date: Option<String>,
    reprompt: u8,
}

#[derive(Debug)]
pub enum CipherData {
    None,
    Login(Box<LoginItem>),
    Card(Box<CardItem>),
    Identity(Box<IdentityItem>),
    SecureNote(Box<SecureNoteItem>),
}

impl From<CipherItemInternal> for CipherItem {
    fn from(cii: CipherItemInternal) -> Self {
        CipherItem {
            id: cii.id,
            key: cii.key,
            name: cii.name,
            notes: cii.notes,
            favorite: cii.favorite,
            collection_ids: cii.collection_ids,
            organization_id: cii.organization_id,
            data: match cii.cipher_type {
                1 => CipherData::Login(Box::new(cii.login.unwrap())),
                2 => CipherData::SecureNote(Box::new(cii.secure_note.unwrap())),
                3 => CipherData::Card(Box::new(cii.card.unwrap())),
                4 => CipherData::Identity(Box::new(cii.identity.unwrap())),
                _ => CipherData::None,
            },
        }
    }
}

#[derive(Debug)]
pub struct CipherItem {
    pub id: String,
    pub name: Cipher,
    pub notes: Cipher,
    pub key: Option<Cipher>,
    pub data: CipherData,
    pub favorite: bool,
    pub collection_ids: Vec<String>,
    pub organization_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all="camelCase")]
pub struct LoginItemUri {
    #[serde(rename = "match")]
    #[serde(alias = "Match")]
    #[serde(default)]
    pub uri_match: Option<i32>,
    #[serde(alias = "Uri")]
    pub uri: Cipher,
    #[serde(alias = "UriChecksum")]
    pub uri_checksum: Cipher
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginItem {
    #[serde(default)]
    #[serde(alias = "Username")]
    pub username: Cipher,
    #[serde(default)]
    #[serde(alias = "Password")]
    pub password: Cipher,
    #[serde(default)]
    #[serde(alias = "Uri")]
    pub uri: Cipher,
    #[serde(default)]
    pub uris: Vec<LoginItemUri>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CardItem {
    #[serde(default)]
    #[serde(alias = "Brand")]
    pub brand: Cipher,
    #[serde(default)]
    #[serde(alias = "CardholderName")]
    #[serde(alias = "cardholderName")]
    pub cardholder_name: Cipher,
    #[serde(default)]
    #[serde(alias = "code")]
    #[serde(alias = "Code")]
    pub code: Cipher,
    #[serde(default)]
    #[serde(alias = "ExpMonth")]
    #[serde(alias = "expMonth")]
    pub exp_month: Cipher,
    #[serde(default)]
    #[serde(alias = "ExpYear")]
    #[serde(alias = "expYear")]
    pub exp_year: Cipher,
    #[serde(default)]
    #[serde(alias = "Number")]
    pub number: Cipher,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IdentityItem {
    #[serde(default)]
    #[serde(alias = "Address1")]
    #[serde(alias = "address1")]
    pub address_1: Cipher,
    #[serde(default)]
    #[serde(alias = "Address2")]
    #[serde(alias = "address2")]
    pub address_2: Cipher,
    #[serde(default)]
    #[serde(alias = "Address3")]
    #[serde(alias = "address3")]
    pub address_3: Cipher,
    #[serde(default)]
    #[serde(alias = "City")]
    pub city: Cipher,
    #[serde(default)]
    #[serde(alias = "Company")]
    pub company: Cipher,
    #[serde(default)]
    #[serde(alias = "Country")]
    pub country: Cipher,
    #[serde(default)]
    #[serde(alias = "Email")]
    pub email: Cipher,
    #[serde(default)]
    #[serde(alias = "FirstName")]
    #[serde(alias = "firstName")]
    pub first_name: Cipher,
    #[serde(default)]
    #[serde(alias = "LastName")]
    #[serde(alias = "lastName")]
    pub last_name: Cipher,
    #[serde(default)]
    #[serde(alias = "LicenseNumber")]
    #[serde(alias = "licenseNumber")]
    pub license_number: Cipher,
    #[serde(default)]
    #[serde(alias = "MiddleName")]
    #[serde(alias = "middleName")]
    pub middle_name: Cipher,
    #[serde(default)]
    #[serde(alias = "PassportNumber")]
    #[serde(alias = "passportNumber")]
    pub passport_number: Cipher,
    #[serde(default)]
    #[serde(alias = "Phone")]
    pub phone: Cipher,
    #[serde(default)]
    #[serde(alias = "PostalCode")]
    #[serde(alias = "postalCode")]
    pub postal_code: Cipher,
    #[serde(default)]
    #[serde(alias = "SSN")]
    pub ssn: Cipher,
    #[serde(default)]
    #[serde(alias = "State")]
    pub state: Cipher,
    #[serde(default)]
    #[serde(alias = "Title")]
    pub title: Cipher,
    #[serde(default)]
    #[serde(alias = "Username")]
    pub username: Cipher,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct SecureNoteItem {
    #[serde(rename="type")]
    #[serde(alias="Type")]
    #[serde(default)]
    pub secure_note_type: i32,
}