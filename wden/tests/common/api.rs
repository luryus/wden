use std::time::Duration;

use reqwest::Url;
use serde::Serialize;
use wden::bitwarden::{api::ApiClient, server::ServerConfiguration};

pub struct VaultwardenClient {
    reqwest: reqwest::Client,
    base_url: Url,
}

impl VaultwardenClient {
    pub fn new(port: u16) -> Self {
        let client = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();

        let base_url = format!("http://127.0.0.1:{port}").parse().unwrap();

        Self {
            reqwest: client,
            base_url,
        }
    }

    pub async fn post<T: Serialize>(&self, path: &str, body: &T) -> Result<(), anyhow::Error> {
        let url = self.base_url.join(path)?;
        self.reqwest
            .post(url)
            .header("Bitwarden-Client-Name", "web")
            .header("Bitwarden-Client-Version", "2024.6.2")
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    pub async fn get_token(&self, username: &str, password: &str) -> anyhow::Result<String> {
        let sc = ServerConfiguration::single_host(self.base_url.clone());
        let cl = ApiClient::new(&sc, "", true);

        let tok = cl.get_token(username, password, None, None).await?;
        match tok {
            wden::bitwarden::api::TokenResponse::Success(token_response_success) => {
                Ok(token_response_success.access_token)
            }
            wden::bitwarden::api::TokenResponse::TwoFactorRequired(_, _) => unreachable!(),
            wden::bitwarden::api::TokenResponse::CaptchaRequired => unreachable!(),
        }
    }
}
