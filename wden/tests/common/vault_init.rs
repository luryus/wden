use super::api::VaultwardenClient;

pub async fn init_vault_data(client: &VaultwardenClient, email: &str, pw_hash: &str) -> anyhow::Result<()> {
    let token = client.get_token(email, pw_hash).await?;

    Ok(())
}