#[cfg(feature = "puppet-integration-tests")]
mod common;

#[cfg(feature = "puppet-integration-tests")]
#[tokio_test_shutdown_timeout::test]
pub(crate) async fn test_normal_flows_pbkdf2() -> anyhow::Result<()> {
    use std::time::Duration;

    use anyhow::Context;
    use cursive::{
        backends::puppet::observed::ObservedPieceInterface,
        event::{Event, Key},
    };
    use wden::bitwarden::server::ServerConfiguration;

    use helpers::*;

    let ctx = common::setup().await?;
    let profile_name = ctx.profile_name.clone();

    let server_config = ServerConfiguration::single_host(
        format!("http://localhost:{}", ctx.http_port)
            .parse()
            .unwrap(),
    );

    println!("Launching...");
    tokio::task::spawn_blocking(|| wden::ui::launch(profile_name, Some(server_config), true, true));

    while wden::ui::launch::CURSIVE_PUPPET_IO.get().is_none() {
        // hack
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let puppet_io = wden::ui::launch::CURSIVE_PUPPET_IO
        .get()
        .context("Failed to get IO")?;
    let input = &puppet_io.0;
    let output = &puppet_io.1;

    // Login
    println!("Logging in...");
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
    let screen = wait_until_string_visible("Vault", output)?;
    println!("Logged in.");

    // Verify all the items are visible
    let item_names = [
        common::testdata::PERSONAL_CARD_1.name,
        common::testdata::PERSONAL_LOGIN_1.name,
        common::testdata::PERSONAL_LOGIN_2.name,
        common::testdata::PERSONAL_LOGIN_3.name,
        common::testdata::PERSONAL_NOTE_1.name,
        common::testdata::PERSONAL_NOTE_2.name,
        common::testdata::ORG_1_COLL_1_LOGIN_1.name,
        common::testdata::ORG_1_COLL_1_LOGIN_2.name,
        common::testdata::ORG_1_COLL_1_LOGIN_3.name,
        common::testdata::ORG_1_COLL_2_LOGIN_1.name,
        common::testdata::ORG_1_COLL_2_LOGIN_2.name,
        common::testdata::ORG_1_COLL_2_LOGIN_3.name,
        common::testdata::ORG_2_COLL_3_LOGIN_1.name,
        common::testdata::ORG_2_COLL_3_LOGIN_2.name,
        common::testdata::ORG_2_COLL_3_LOGIN_3.name,
    ];
    for n in item_names {
        assert!(!screen.find_occurences(n).is_empty());
    }

    // Open the org 1 coll 1 login 1 item by cilicking the row twice
    let pos = screen
        .find_occurences(common::testdata::ORG_1_COLL_1_LOGIN_1.name)
        .first()
        .unwrap()
        .min();
    click_position(pos, input)?;
    click_position(pos, input)?;

    let screen = wait_until_string_visible("Uri", output)?;
    assert!(
        !screen
            .find_occurences(common::testdata::ORG_1_COLL_1_LOGIN_1.name)
            .is_empty()
    );
    assert!(
        !screen
            .find_occurences(common::testdata::ORG_1_COLL_1_LOGIN_1.username)
            .is_empty()
    );
    assert!(
        !screen
            .find_occurences(common::testdata::ORG_1_COLL_1_LOGIN_1.uri)
            .is_empty()
    );
    assert!(
        !screen
            .find_occurences(common::testdata::ORG_1_COLL_1_LOGIN_1.notes)
            .is_empty()
    );
    assert!(!screen.find_occurences("*****").is_empty());

    input.send(Some(Event::Char('s')))?;
    wait_until_string_visible(common::testdata::ORG_1_COLL_1_LOGIN_1.password, output)?;

    input.send_timeout(Some(Event::Exit), Duration::from_secs(1))?;

    Ok(())
}

#[cfg(feature = "puppet-integration-tests")]
mod helpers {
    use std::time::{Duration, Instant};

    use cursive::{
        XY,
        backends::puppet::observed::ObservedScreen,
        event::Event,
        reexports::crossbeam_channel::{Receiver, RecvTimeoutError, SendError, Sender},
    };

    pub(super) fn wait_until_string_visible(
        needle: &str,
        recv: &Receiver<ObservedScreen>,
    ) -> Result<ObservedScreen, RecvTimeoutError> {
        const TIMEOUT: Duration = Duration::from_secs(15);
        let deadline = Instant::now() + TIMEOUT;

        while Instant::now() < deadline {
            let r = recv.recv_deadline(deadline)?;
            if !r.find_occurences(needle).is_empty() {
                return Ok(r);
            }
        }

        Err(RecvTimeoutError::Timeout)
    }

    #[cfg(feature = "puppet-integration-tests")]
    pub(super) fn send_string(
        text: &str,
        sender: &Sender<Option<Event>>,
    ) -> Result<(), SendError<Option<Event>>> {
        for c in text.chars() {
            let ev = Some(Event::Char(c));
            sender.send(ev)?;
        }
        Ok(())
    }

    #[cfg(feature = "puppet-integration-tests")]
    pub(super) fn click_position(
        pos: XY<usize>,
        sender: &Sender<Option<Event>>,
    ) -> Result<(), SendError<Option<Event>>> {
        sender.send(Some(Event::Mouse {
            offset: XY::zero(),
            position: pos,
            event: cursive::event::MouseEvent::Press(cursive::event::MouseButton::Left),
        }))?;
        sender.send(Some(Event::Mouse {
            offset: XY::zero(),
            position: pos,
            event: cursive::event::MouseEvent::Release(cursive::event::MouseButton::Left),
        }))?;
        Ok(())
    }
}
