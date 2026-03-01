use wden::bitwarden::cipher::{self};

use super::api::{CreateCollectionResponse, CreateOrganizationResponse, VaultwardenClient};

pub async fn init_vault_data(
    client: &mut VaultwardenClient,
    email: &str,
    pw_hash: &str,
    password: &[u8],
) -> anyhow::Result<()> {
    let mut token = client.get_token(email, pw_hash).await?;
    client.set_access_token(std::mem::take(&mut token.access_token));

    let master_key =
        cipher::create_master_key(email, password, &token.pbkdf_parameters().unwrap())?;
    let enc_mac = cipher::decrypt_symmetric_keys(&token.key, &master_key)?;
    let dec_private_key = token.private_key.decrypt(&enc_mac)?.into();

    let orgs = super::testdata::organizations(email, &dec_private_key);
    let mut org_ids_keys = vec![];

    for (org, keys) in orgs {
        let resp: CreateOrganizationResponse =
            client.post_response("/api/organizations", &org).await?;
        org_ids_keys.push((resp.id, keys));
    }

    let colls = super::testdata::collections(&org_ids_keys);
    let mut collection_ids = vec![];
    for c in colls {
        let coll_resp: CreateCollectionResponse = client
            .post_response(&format!("/api/organizations/{}/collections", &c.org_id), &c)
            .await?;
        collection_ids.push(coll_resp.id);
    }

    let items = super::testdata::items(&enc_mac, &org_ids_keys, &collection_ids)?;
    for item in items {
        if item.collection_ids.is_empty() {
            // Personal
            client.post("/api/ciphers", &item.cipher).await?;
        } else {
            // Org
            client.post("/api/ciphers/create", &item).await?;
        }
    }

    Ok(())
}
