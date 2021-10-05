use std::time::Duration;

use clipboard::{ClipboardContext, ClipboardProvider};

pub fn clip_string(s: String) {
    let mut cx: ClipboardContext =
        ClipboardProvider::new().expect("Building clipboard provider failed");
    cx.set_contents(s).expect("Clipping failed");
}

pub fn clip_exipiring_string(s: String, expiry_seconds: u64) {
    tokio::spawn(async move {
        let mut cx: ClipboardContext =
            ClipboardProvider::new().expect("Building clipboard provider failed");

        cx.set_contents(s.clone()).expect("Clipping failed");
        tokio::time::sleep(Duration::from_secs(expiry_seconds)).await;
        let res = cx.get_contents().and_then(|curr_contents| {
            if curr_contents == s {
                cx.set_contents(String::new())
            } else {
                Ok(())
            }
        });

        if let Err(e) = res {
            log::warn!("Clearing clipboard failed: {}", e);
        }
    });
}
