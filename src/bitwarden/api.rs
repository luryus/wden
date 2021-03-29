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
        body.insert("deviceName", "wardenwise");
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
        let url = self.base_url.join("api/sync")?;
        let res = self.http_client.get(url)
            .bearer_auth(self.access_token.as_ref().unwrap())
            .send().await?
            .error_for_status()?
            .json::<SyncResponse>().await?;

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
pub struct SyncResponse {
    pub ciphers: Vec<CipherItem>
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CipherItem {
    pub id: String,
    #[serde(alias = "Type")]
    pub cipher_type: i32,
    pub name: Option<Cipher>,
    pub notes: Option<Cipher>,
    pub login: Option<LoginItem>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct LoginItem {
    pub username: Option<Cipher>,
    pub password: Option<Cipher>
}
