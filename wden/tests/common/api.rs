use std::time::Duration;

use reqwest::{RequestBuilder, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use wden::bitwarden::{
    api::{ApiClient, CipherData, CipherItem, TokenResponseSuccess},
    cipher::Cipher,
    server::ServerConfiguration,
};

pub struct VaultwardenClient {
    reqwest: reqwest::Client,
    base_url: Url,
    access_token: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationKeyPair {
    pub encrypted_private_key: Cipher,
    pub public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrganizationRequest {
    pub key: Cipher,
    pub keys: OrganizationKeyPair,
    pub name: &'static str,
    pub billing_email: String,
    pub collection_name: Cipher,
    pub plan_type: u8,
    pub initiation_path: &'static str,
}

#[derive(Deserialize)]
pub struct CreateOrganizationResponse {
    pub id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCollectionRequest {
    pub name: Cipher,
    pub external_id: &'static str,
    pub groups: [&'static str; 0],
    pub users: [&'static str; 0],
    #[serde(skip)]
    pub org_id: String,
}

#[derive(Deserialize)]
pub struct CreateCollectionResponse {
    pub id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePersonalCipherRequest {
    #[serde(rename = "type")]
    pub cipher_type: i32,
    pub name: Cipher,
    pub notes: Cipher,
    pub login: Option<wden::bitwarden::api::LoginItem>,
    pub card: Option<wden::bitwarden::api::CardItem>,
    pub identity: Option<wden::bitwarden::api::IdentityItem>,
    pub secure_note: Option<wden::bitwarden::api::SecureNoteItem>,
    pub favorite: bool,
    pub collection_ids: Vec<String>,
    pub organization_id: Option<String>,
    pub last_known_revision_date: Option<String>,
    pub reprompt: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrgCipherRequest {
    pub cipher: CreatePersonalCipherRequest,
    pub collection_ids: Vec<String>,
}

impl From<CipherItem> for CreatePersonalCipherRequest {
    fn from(item: CipherItem) -> Self {
        let (cipher_type, login, card, identity, note) = match item.data {
            CipherData::None => (0, None, None, None, None),
            CipherData::Login(login_item) => (1, Some(login_item), None, None, None),
            CipherData::Card(card_item) => (3, None, Some(card_item), None, None),
            CipherData::Identity(identity_item) => (4, None, None, Some(identity_item), None),
            CipherData::SecureNote(note_item) => (2, None, None, None, Some(note_item)),
        };

        CreatePersonalCipherRequest {
            cipher_type,
            name: item.name,
            notes: item.notes,
            login: login.map(|x| *x),
            card: card.map(|x| *x),
            identity: identity.map(|x| *x),
            secure_note: note.map(|x| *x),
            favorite: item.favorite,
            collection_ids: item.collection_ids,
            organization_id: item.organization_id,
            reprompt: 0,
            last_known_revision_date: None,
        }
    }
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
            access_token: None,
        }
    }

    pub fn set_access_token(&mut self, access_token: String) {
        self.access_token = Some(access_token);
    }

    pub async fn post<T: Serialize>(&self, path: &str, body: &T) -> Result<(), anyhow::Error> {
        self.get_post_req(path, body)?
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn post_response<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, anyhow::Error> {
        let resp = self
            .get_post_req(path, body)?
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(resp)
    }

    fn get_post_req<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<RequestBuilder, anyhow::Error> {
        let url = self.base_url.join(path)?;
        let req = self
            .reqwest
            .post(url)
            .header("Bitwarden-Client-Name", "cli")
            .header("Bitwarden-Client-Version", "2024.6.2")
            .json(&body);

        if let Some(acctok) = &self.access_token {
            Ok(req.bearer_auth(acctok))
        } else {
            Ok(req)
        }
    }

    pub async fn get_token(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Box<TokenResponseSuccess>> {
        let sc = ServerConfiguration::single_host(self.base_url.clone());
        let cl = ApiClient::new(&sc, "", true);

        let tok = cl.get_token(username, password, None, None).await?;
        match tok {
            wden::bitwarden::api::TokenResponse::Success(token_response_success) => {
                Ok(token_response_success)
            }
            wden::bitwarden::api::TokenResponse::TwoFactorRequired(_, _) => unreachable!(),
            wden::bitwarden::api::TokenResponse::CaptchaRequired => unreachable!(),
        }
    }
}
