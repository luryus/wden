use api::VaultwardenClient;
use testcontainers::{
    core::{IntoContainerPort, WaitFor}, runners::AsyncRunner, ContainerAsync, GenericImage, ImageExt
};
use user_init::{PBKDF2_USER_EMAIL, PBKDF2_USER_MASTER_PW_HASH, PBKDF2_USER_PASSWORD};


mod user_init;
mod vault_init;
mod api;
pub mod testdata;

pub struct IntegrationTestContext {
    _container: ContainerAsync<GenericImage>,
    _client: VaultwardenClient,
    pub http_port: u16,
}

pub async fn setup() -> anyhow::Result<IntegrationTestContext> {
    let container = testcontainers::GenericImage::new("docker.io/vaultwarden/server", "latest")
        .with_exposed_port(80.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Rocket has launched"))
        .with_env_var("I_REALLY_WANT_VOLATILE_STORAGE", "true")
        .start()
        .await?;

    let http_port = container.get_host_port_ipv4(80.tcp()).await?;
    let mut client = VaultwardenClient::new(http_port);

    user_init::init_users(&client).await?;

    vault_init::init_vault_data(&mut client, PBKDF2_USER_EMAIL, PBKDF2_USER_MASTER_PW_HASH, PBKDF2_USER_PASSWORD).await?;

    Ok(IntegrationTestContext {
        _container: container,
        _client: client,
        http_port,
    })
}

