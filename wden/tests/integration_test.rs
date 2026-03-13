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
        common::testdata::PERSONAL_LOGIN_WITH_ATTACHMENT.name,
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
    let screen =
        wait_until_string_visible(common::testdata::ORG_1_COLL_1_LOGIN_1.password, output)?;

    // Close the item detail dialog by clicking the Close button
    let pos = screen.find_occurences("Close").first().unwrap().min();
    click_position(pos, input)?;

    // Open the item with an attachment
    let screen = wait_until_string_visible(
        common::testdata::PERSONAL_LOGIN_WITH_ATTACHMENT.name,
        output,
    )?;
    let pos = screen
        .find_occurences(common::testdata::PERSONAL_LOGIN_WITH_ATTACHMENT.name)
        .first()
        .unwrap()
        .min();
    click_position(pos, input)?;
    click_position(pos, input)?;

    // Verify attachment info is shown in item details
    let screen = wait_until_string_visible("Download attachment", output)?;
    assert!(
        !screen
            .find_occurences(common::testdata::ATTACHMENT_1.attachment_filename)
            .is_empty()
    );

    // Press 'd' to download — since there's 1 attachment, goes directly to file browser
    input.send(Some(Event::Char('d')))?;
    let screen = wait_until_string_visible("Save attachment", output)?;
    // Verify the default filename is pre-filled
    assert!(
        !screen
            .find_occurences(common::testdata::ATTACHMENT_1.attachment_filename)
            .is_empty()
    );

    // Determine expected save directory (same logic as file browser's default_start_dir)
    let save_dir = {
        let mut dir = std::env::temp_dir();
        if let Some(user_dirs) = directories_next::UserDirs::new() {
            if user_dirs.download_dir().is_some_and(|d| d.is_dir()) {
                dir = user_dirs.download_dir().unwrap().to_path_buf();
            } else if user_dirs.home_dir().is_dir() {
                dir = user_dirs.home_dir().to_path_buf();
            }
        }
        dir
    };

    // Use a unique filename to avoid conflicts
    let unique_filename = format!("wden_test_{}.txt", uuid::Uuid::new_v4());
    let expected_save_path = save_dir.join(&unique_filename);

    // Tab to the filename EditView (from the directory list)
    input.send(Some(Event::Key(Key::Tab)))?;
    // Select all text in the edit field and replace with our unique filename
    input.send(Some(Event::CtrlChar('u')))?;
    send_string(&unique_filename, input)?;

    // Tab to Save button and press Enter
    input.send(Some(Event::Key(Key::Tab)))?;
    input.send(Some(Event::Key(Key::Enter)))?;

    // Wait for download to complete
    wait_until_string_visible("Download complete", output)?;

    // Verify file content matches original
    let saved_content = std::fs::read(&expected_save_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read saved file {}: {e}",
            expected_save_path.display()
        )
    });
    assert_eq!(
        saved_content,
        common::testdata::ATTACHMENT_1.attachment_content,
        "Downloaded file content does not match original"
    );

    // Clean up the downloaded file
    let _ = std::fs::remove_file(&expected_save_path);

    // Dismiss the download complete dialog
    input.send(Some(Event::Key(Key::Enter)))?;

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
