use std::time::Duration;

#[cfg(windows)]
mod windows_clipboard;
#[cfg(windows)]
type PlatformCbImpl = windows_clipboard::WindowsClipboard;

#[cfg(target_os = "linux")]
mod linux_clipboard;
#[cfg(target_os = "linux")]
type PlatformCbImpl = linux_clipboard::LinuxClipboard;

pub fn clip_string(s: String) {
    log::info!("Clipping...");
    if let Err(e) = PlatformCbImpl::clip_string(s) {
        log::warn!("Clipping string failed: {e}")
    };
}

pub fn clip_expiring_string(s: String, expiry_seconds: u64) {
    tokio::spawn(async move {
        clip_string(s.clone());
        tokio::time::sleep(Duration::from_secs(expiry_seconds)).await;
        let res = PlatformCbImpl::get_string_contents().and_then(|curr_contents| {
            if curr_contents == s {
                log::info!("Clearing clipboard...");
                PlatformCbImpl::clear()
            } else {
                Ok(())
            }
        });

        if let Err(e) = res {
            log::warn!("Clearing clipboard failed: {e}");
        }
    });
}

type PlatformClipboardResult<T> = Result<T, anyhow::Error>;

trait PlatformClipboard {
    fn clip_string(s: String) -> PlatformClipboardResult<()>;

    fn get_string_contents() -> PlatformClipboardResult<String>;

    fn clear() -> PlatformClipboardResult<()>;
}
