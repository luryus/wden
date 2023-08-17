use std::fmt::Display;

use clap::ValueEnum;
use reqwest::Url;
use serde::{Deserialize, Serialize};

const BITWARDEN_CLOUD_US_API: &str = "https://api.bitwarden.com";
const BITWARDEN_CLOUD_US_IDENTITY: &str = "https://identity.bitwarden.com";

const BITWARDEN_CLOUD_EU_API: &str = "https://api.bitwarden.eu";
const BITWARDEN_CLOUD_EU_IDENTITY: &str = "https://identity.bitwarden.eu";

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BaseUrl(Url);

impl Serialize for BaseUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for BaseUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Url::parse(&s)
            .map(BaseUrl)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Default, Serialize, Deserialize, ValueEnum, PartialEq, Eq, Debug)]
pub enum BitwardenCloudRegion {
    #[default]
    US,
    EU,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum ServerConfiguration {
    BitwardenCloud(BitwardenCloudRegion),
    SingleHost {
        url: BaseUrl,
    },
    ApiAndIdentityHost {
        api_url: BaseUrl,
        identity_url: BaseUrl,
    },
}

impl Default for ServerConfiguration {
    fn default() -> Self {
        Self::BitwardenCloud(Default::default())
    }
}

impl Display for ServerConfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerConfiguration::BitwardenCloud(BitwardenCloudRegion::US) => {
                write!(f, "Bitwarden Cloud (US)")
            }
            ServerConfiguration::BitwardenCloud(BitwardenCloudRegion::EU) => {
                write!(f, "Bitwarden Cloud (EU)")
            }
            ServerConfiguration::SingleHost { url } => write!(f, "{}", url.0),
            ServerConfiguration::ApiAndIdentityHost {
                api_url,
                identity_url,
            } => write!(f, "{}, {}", api_url.0, identity_url.0),
        }
    }
}

fn ensure_trailing_slash(url: &mut Url) {
    if let Ok(mut segs) = url.path_segments_mut() {
        segs.pop_if_empty().push("");
    }
}

impl ServerConfiguration {
    pub fn cloud(region: BitwardenCloudRegion) -> Self {
        Self::BitwardenCloud(region)
    }

    pub fn single_host(mut url: Url) -> Self {
        ensure_trailing_slash(&mut url);
        Self::SingleHost { url: BaseUrl(url) }
    }

    pub fn separate_hosts(mut api_url: Url, mut identity_url: Url) -> Self {
        ensure_trailing_slash(&mut api_url);
        ensure_trailing_slash(&mut identity_url);

        Self::ApiAndIdentityHost {
            api_url: BaseUrl(api_url),
            identity_url: BaseUrl(identity_url),
        }
    }

    pub fn api_base_url(&self) -> Url {
        match self {
            Self::BitwardenCloud(BitwardenCloudRegion::US) => {
                Url::parse(BITWARDEN_CLOUD_US_API).unwrap()
            }
            Self::BitwardenCloud(BitwardenCloudRegion::EU) => {
                Url::parse(BITWARDEN_CLOUD_EU_API).unwrap()
            }
            Self::SingleHost { url } => url.0.join("/api/").unwrap(),
            Self::ApiAndIdentityHost {
                api_url,
                identity_url: _,
            } => api_url.0.clone(),
        }
    }

    pub fn identity_base_url(&self) -> Url {
        match self {
            Self::BitwardenCloud(BitwardenCloudRegion::US) => {
                Url::parse(BITWARDEN_CLOUD_US_IDENTITY).unwrap()
            }
            Self::BitwardenCloud(BitwardenCloudRegion::EU) => {
                Url::parse(BITWARDEN_CLOUD_EU_IDENTITY).unwrap()
            }
            Self::SingleHost { url } => url.0.join("/identity/").unwrap(),
            Self::ApiAndIdentityHost {
                api_url: _,
                identity_url,
            } => identity_url.0.clone(),
        }
    }
}
