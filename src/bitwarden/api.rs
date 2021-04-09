use itertools::Itertools;
use reqwest;
use reqwest::Url;
use std::collections::HashMap;
use failure::{Error, err_msg};
use serde_json::Value;
use serde::Deserialize;
use super::cipher::Cipher;

// Name your user agent after your app?
static APP_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);

pub struct ApiClient {
    http_client: reqwest::Client,
    base_url: Url,

    access_token: Option<String>
}

impl ApiClient {
    pub fn new() -> Self {
        let http_client = reqwest::Client::builder()
            .user_agent(APP_USER_AGENT)
            .build().unwrap();
        let base_url = Url::parse("http://localhost:8082/").unwrap();
        ApiClient { http_client, base_url, access_token: None }
    }

    pub fn with_token(token: &str) -> Self {
        let mut c = Self::new();
        c.access_token = Some(token.to_string());
        return c;
    }

    pub async fn prelogin(&self, user_email: &str) -> Result<usize, Error> {
        let mut body = HashMap::new();
        body.insert("email", user_email);

        let url = self.base_url.join("api/accounts/prelogin")?;

        let res = self.http_client.post(url)
            .json(&body)
            .send().await?
            .error_for_status()?;

        let res: Value = res.json().await?;

        let iterations = res.as_object()
            .and_then(|o| o.get("KdfIterations"))
            .and_then(|v| v.as_u64()).ok_or(err_msg("Parsing response failed"))?;

        Ok(iterations as usize)
    }

    pub async fn get_token(&self, username: &str, password: &str) -> Result<TokenResponse, Error> {
        let mut body = HashMap::new();
        body.insert("grant_type", "password");
        body.insert("username", username);
        body.insert("password", password);
        body.insert("scope", "api offline_access");
        body.insert("client_id", "web");
        body.insert("deviceName", "bitwarden-tui");
        body.insert("deviceIdentifier", "asd");
        body.insert("deviceType", "9");

        let url = self.base_url.join("identity/connect/token")?;

        let res = self.http_client.post(url)
            .form(&body)
            .send().await?
            .error_for_status()?
            .json::<TokenResponse>().await?;

        return Ok(res)
    }

    pub async fn sync(&self) -> Result<SyncResponse, Error> {
        assert!(self.access_token.is_some());
        let mut url = self.base_url.join("api/sync")?;
        url.set_query(Some("excludeDomains=true"));
        let res = self.http_client.get(url)
            .bearer_auth(self.access_token.as_ref().unwrap())
            .send().await?
            .error_for_status()?
            .json::<SyncResponseInternal>().await?
            .into();

        return Ok(res);
    }
}

#[derive(Deserialize, Debug)]
pub struct TokenResponse {
    #[serde(alias = "Key")]
    pub key: Cipher,
    #[serde(alias = "PrivateKey")]
    private_key: Cipher,
    pub access_token: String,
    expires_in: u32,
    refresh_token: String,
    token_type: String
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct SyncResponseInternal {
    ciphers: Vec<CipherItemInternal>
}

pub struct SyncResponse {
    pub ciphers: Vec<CipherItem>
}

impl From<SyncResponseInternal> for SyncResponse {
    fn from(sri: SyncResponseInternal) -> Self {
        SyncResponse {
            ciphers: sri.ciphers.into_iter().map_into::<CipherItem>().collect_vec()
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
    organization_id: Option<String>
}

#[derive(Debug)]
pub enum CipherData {
    None,
    Login(LoginItem),
    Card(CardItem),
    Identity(IdentityItem),
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
                1 => CipherData::Login(cii.login.unwrap()),
                2 => CipherData::SecureNote,
                3 => CipherData::Card(cii.card.unwrap()),
                4 => CipherData::Identity(cii.identity.unwrap()),
                _ => CipherData::None
            }
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
    pub organization_id: Option<String>
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
