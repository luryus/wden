use clipboard_win::{
    formats::Unicode, get_clipboard_string, raw::set, register_format, Clipboard, Setter,
};

pub fn clip_string_internal(s: String) -> Result<(), anyhow::Error> {
    let _cb = Clipboard::new_attempts(10)?;

    // First add something with this custom format, to make Windows
    // bypass clipboard history
    let history_exc_format = register_format("ExcludeClipboardContentFromMonitorProcessing");
    if let Some(hef) = history_exc_format {
        set(hef.get(), &[])?;
    }

    Unicode.write_clipboard(&s)?;

    Ok(())
}

pub fn get_string_contents_internal() -> Result<String, anyhow::Error> {
    Ok(get_clipboard_string()?)
}
