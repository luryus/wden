use wden::bitwarden::api::*;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {

    let client = ApiClient::new(
        "https://vault.bitwarden.com",
        "foo",
        true
    );

    let _res = client.get_token("foo", "bar", None, None).await?;

    Ok(())
}
