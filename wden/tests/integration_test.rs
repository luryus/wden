use std::time::{Duration, Instant};

use anyhow::Context;
use cursive::{
    backends::puppet::observed::ObservedScreen,
    event::{Event, Key},
    reexports::crossbeam_channel::{Receiver, RecvTimeoutError, SendError, Sender},
};
use wden::bitwarden::server::ServerConfiguration;

mod common;

#[cfg(feature = "puppet-integration-tests")]
#[test]
fn test1() {
    use std::panic::{catch_unwind, resume_unwind};

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let res = catch_unwind(|| runtime.block_on(test1async()));
    runtime.shutdown_background();
    if let Err(e) = res {
        resume_unwind(e);
    }
}

async fn test1async() -> anyhow::Result<()> {
    let ctx = common::setup().await?;

    let profile_name = uuid::Uuid::new_v4().to_string();
    let server_config = ServerConfiguration::single_host(
        format!("http://localhost:{}", ctx.http_port).parse().unwrap());

    tokio::task::spawn_blocking(|| wden::ui::launch(profile_name, Some(server_config), true, true));

    while wden::ui::launch::CURSIVE_PUPPET_IO.get().is_none() {
        // hack
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let puppet_io = wden::ui::launch::CURSIVE_PUPPET_IO.get().context("Failed to get IO")?;
    let input = &puppet_io.0;
    let output = &puppet_io.1;

    // Login
    wait_until_string_visible("Log in", output)?;
    send_string("test.pbkdf2@example.com", input)?;
    input.send(Some(Event::Key(Key::Tab)))?;
    send_string("testpassword", input)?;
    input.send(Some(Event::Key(Key::Enter)))?;
    wait_until_string_visible("Vault", output)?;

    // Lock and unlock
    input.send(Some(Event::CtrlChar('l')))?;
    wait_until_string_visible("Vault locked", output)?;
    send_string("testpassword", input)?;
    input.send(Some(Event::Key(Key::Enter)))?;
    wait_until_string_visible("Vault", output)?;

    input.send_timeout(Some(Event::Exit), Duration::from_secs(1))?;

    Ok(())
}

fn wait_until_string_visible(
    needle: &str,
    recv: &Receiver<ObservedScreen>,
) -> Result<(), RecvTimeoutError> {
    const TIMEOUT: Duration = Duration::from_secs(15);
    let deadline = Instant::now() + TIMEOUT;

    while Instant::now() < deadline {
        let r = recv.recv_deadline(deadline)?;
        if !r.find_occurences(needle).is_empty() {
            return Ok(());
        }
    }

    Err(RecvTimeoutError::Timeout)
}

fn send_string(text: &str, sender: &Sender<Option<Event>>) -> Result<(), SendError<Option<Event>>> {
    for c in text.chars() {
        let ev = Some(Event::Char(c));
        sender.send(ev)?;
    }
    Ok(())
}
