use super::cipher::Cipher;
use anyhow::Error;
use itertools::Itertools;
use reqwest;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use std::convert::TryInto;
use std::time::{Duration, Instant};
use std::{collections::HashMap, convert::TryFrom};

// Name your user agent after your app?
static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

pub static DEFAULT_SERVER_URL: &str = "http://localhost:8082/";

#[allow(clippy::enum_variant_names)]
enum DeviceType {
    WindowsDesktop = 6,
    MacOsDesktop = 7,
    LinuxDesktop = 8,
}

const fn get_device_type() -> DeviceType {
    if cfg!(windows) {
        DeviceType::WindowsDesktop
    } else if cfg!(macos) {
        DeviceType::MacOsDesktop
    } else {
        DeviceType::LinuxDesktop
    }
}

pub struct ApiClient {
    http_client: reqwest::Client,
    base_url: Url,
    device_identifier: String,
    access_token: Option<String>,
}

impl ApiClient {
    pub fn new(server_url: &str, device_identifier: String) -> Self {
        let http_client = reqwest::Client::builder()
            .user_agent(APP_USER_AGENT)
            .build()
            .unwrap();
        let base_url = Url::parse(server_url).unwrap();
        ApiClient {
            http_client,
            base_url,
            device_identifier,
            access_token: None,
        }
    }

    pub fn with_token(server_url: &str, device_identifier: String, token: &str) -> Self {
        let mut c = Self::new(server_url, device_identifier);
        c.access_token = Some(token.to_string());
        c
    }

    pub async fn prelogin(&self, user_email: &str) -> Result<u32, Error> {
        let mut body = HashMap::new();
        body.insert("email", user_email);

        let url = self.base_url.join("api/accounts/prelogin")?;

        let res = self
            .http_client
            .post(url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        let res: Value = res.json().await?;

        let iterations = res
            .as_object()
            .and_then(|o| o.get("KdfIterations"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Parsing response failed"))?;

        Ok(iterations as u32)
    }

    pub async fn get_token(
        &self,
        username: &str,
        password: &str,
        two_factor: Option<(TwoFactorProviderType, &str, bool)>,
    ) -> Result<TokenResponse, Error> {
        let device_type = (get_device_type() as i8).to_string();
        let mut body = HashMap::new();
        body.insert("grant_type", "password");
        body.insert("username", username);
        body.insert("password", password);
        body.insert("scope", "api offline_access");
        body.insert("client_id", "cli");
        body.insert("deviceName", "wden");
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

        let url = self.base_url.join("identity/connect/token")?;

        let res = self.http_client.post(url)
            .form(&body)
            // As of October 2021, Bitwarden (prod) wants the email as base64-encoded in a header
            // for some security reason
            .header("auth-email", base64::encode_config(username, base64::URL_SAFE))
            .send().await?;

        if res.status() == 400 {
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
                            .collect_vec()
                    })
                    .ok_or_else(|| anyhow::anyhow!("Error parsing provider types"))?;

                return Ok(TokenResponse::TwoFactorRequired(providers));
            } else {
                return Err(anyhow::anyhow!("Error logging in: {:?}", body));
            }
        }

        let res = res
            .error_for_status()?
            .json::<TokenResponseSuccess>()
            .await?;

        Ok(TokenResponse::Success(res))
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse, Error> {
        let mut body = HashMap::new();
        body.insert("grant_type", "refresh_token");
        body.insert("refresh_token", refresh_token);

        let url = self.base_url.join("identity/connect/token")?;

        let res = self.http_client.post(url).form(&body).send().await?;

        let res = res
            .error_for_status()?
            .json::<TokenResponseSuccess>()
            .await?;

        Ok(TokenResponse::Success(res))
    }

    pub async fn sync(&self) -> Result<SyncResponse, Error> {
        assert!(self.access_token.is_some());
        let mut url = self.base_url.join("api/sync")?;
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
    Success(TokenResponseSuccess),
    TwoFactorRequired(Vec<TwoFactorProviderType>),
}

#[derive(Deserialize, Debug)]
pub struct TokenResponseSuccess {
    #[serde(alias = "Key")]
    pub key: Cipher,
    #[serde(alias = "PrivateKey")]
    pub private_key: Cipher,
    pub access_token: String,
    expires_in: u32,
    pub refresh_token: String,
    #[serde(alias = "TwoFactorToken")]
    pub two_factor_token: Option<String>,
    #[serde(skip, default = "token_response_timestamp")]
    token_timestamp: Instant,
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
}

fn token_response_timestamp() -> Instant {
    Instant::now()
}

#[derive(PartialEq, Copy, Clone, Debug)]
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

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct SyncResponseInternal {
    ciphers: Vec<CipherItemInternal>,
    profile: Profile,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Profile {
    pub email: String,
    pub id: String,
    pub name: String,
    pub organizations: Vec<Organization>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Organization {
    pub enabled: bool,
    pub id: String,
    #[serde(default)]
    pub key: Cipher,
    pub name: String,
}

pub struct SyncResponse {
    pub ciphers: Vec<CipherItem>,
    pub profile: Profile,
}

impl From<SyncResponseInternal> for SyncResponse {
    fn from(sri: SyncResponseInternal) -> Self {
        SyncResponse {
            ciphers: sri
                .ciphers
                .into_iter()
                .map_into::<CipherItem>()
                .collect_vec(),
            profile: sri.profile,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct CipherItemInternal {
    id: String,
    #[serde(alias = "Type")]
    cipher_type: i32,
    #[serde(default)]
    name: Cipher,
    #[serde(default)]
    notes: Cipher,
    login: Option<LoginItem>,
    card: Option<CardItem>,
    identity: Option<IdentityItem>,
    favorite: bool,
    collection_ids: Vec<String>,
    organization_id: Option<String>,
}

#[derive(Debug)]
pub enum CipherData {
    None,
    Login(Box<LoginItem>),
    Card(Box<CardItem>),
    Identity(Box<IdentityItem>),
    SecureNote,
}

impl From<CipherItemInternal> for CipherItem {
    fn from(cii: CipherItemInternal) -> Self {
        CipherItem {
            id: cii.id,
            name: cii.name,
            notes: cii.notes,
            favorite: cii.favorite,
            collection_ids: cii.collection_ids,
            organization_id: cii.organization_id,
            data: match cii.cipher_type {
                1 => CipherData::Login(Box::new(cii.login.unwrap())),
                2 => CipherData::SecureNote,
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
    pub data: CipherData,
    pub favorite: bool,
    pub collection_ids: Vec<String>,
    pub organization_id: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct LoginItem {
    #[serde(default)]
    pub username: Cipher,
    #[serde(default)]
    pub password: Cipher,
    #[serde(default)]
    pub uri: Cipher,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CardItem {
    #[serde(default)]
    pub brand: Cipher,
    #[serde(default)]
    pub card_holder_name: Cipher,
    #[serde(default)]
    pub code: Cipher,
    #[serde(default)]
    pub exp_month: Cipher,
    #[serde(default)]
    pub exp_year: Cipher,
    #[serde(default)]
    pub number: Cipher,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct IdentityItem {
    #[serde(default)]
    pub address_1: Cipher,
    #[serde(default)]
    pub address_2: Cipher,
    #[serde(default)]
    pub address_3: Cipher,
    #[serde(default)]
    pub city: Cipher,
    #[serde(default)]
    pub company: Cipher,
    #[serde(default)]
    pub country: Cipher,
    #[serde(default)]
    pub email: Cipher,
    #[serde(default)]
    pub first_name: Cipher,
    #[serde(default)]
    pub last_name: Cipher,
    #[serde(default)]
    pub license_number: Cipher,
    #[serde(default)]
    pub middle_name: Cipher,
    #[serde(default)]
    pub passport_number: Cipher,
    #[serde(default)]
    pub phone: Cipher,
    #[serde(default)]
    pub postal_code: Cipher,
    #[serde(alias = "SSN")]
    #[serde(default)]
    pub ssn: Cipher,
    #[serde(default)]
    pub state: Cipher,
    #[serde(default)]
    pub title: Cipher,
    #[serde(default)]
    pub username: Cipher,
}
