use std::time::Duration;

#[cfg(target_os = "windows")]
mod windows_clipboard;
#[cfg(target_os = "windows")]
use windows_clipboard::*;

#[cfg(target_os = "linux")]
mod linux_clipboard;
#[cfg(target_os = "linux")]
use linux_clipboard::*;

pub fn clip_string(s: String) {
    log::warn!("Clipping!");
    if let Err(e) = clip_string_internal(s) {
        log::warn!("Clipping string failed: {}", e)
    };
}

pub fn clip_expiring_string(s: String, expiry_seconds: u64) {
    tokio::spawn(async move {
        clip_string(s.clone());
        tokio::time::sleep(Duration::from_secs(expiry_seconds)).await;
        let res = get_string_contents_internal().and_then(|curr_contents| {
            if curr_contents == s {
                clip_string_internal(String::new())
            } else {
                Ok(())
            }
        });

        if let Err(e) = res {
            log::warn!("Clearing clipboard failed: {}", e);
        }
    });
}
