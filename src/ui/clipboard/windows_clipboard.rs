use super::{PlatformClipboard, PlatformClipboardResult};
use clipboard_win::{
    formats::Unicode,
    get_clipboard_string,
    raw::{empty, set_without_clear},
    register_format, Clipboard, Setter,
};

pub struct WindowsClipboard;

impl PlatformClipboard for WindowsClipboard {
    fn clip_string(s: String) -> PlatformClipboardResult<()> {
        let _cb = Clipboard::new_attempts(10)?;

        Unicode.write_clipboard(&s)?;

        // Add something with this custom format, to make Windows
        // bypass clipboard history
        let history_exc_format = register_format("ExcludeClipboardContentFromMonitorProcessing");
        if let Some(hef) = history_exc_format {
            set_without_clear(hef.get(), &[0])?;
        }

        Ok(())
    }

    fn get_string_contents() -> PlatformClipboardResult<String> {
        Ok(get_clipboard_string()?)
    }

    fn clear() -> PlatformClipboardResult<()> {
        let _cb = Clipboard::new_attempts(10)?;
        empty()?;
        Ok(())
    }
}
