use std::sync::OnceLock;

static PANIC_MSG: OnceLock<Option<String>> = OnceLock::new();

pub struct PanicHandler;

impl PanicHandler {
    pub fn new() -> Self {
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            use cursive::backends::crossterm::crossterm::*;
            _ = execute!(
                std::io::stdout(),
                terminal::LeaveAlternateScreen,
                cursor::Show,
                event::DisableMouseCapture,
            );
            _ = terminal::disable_raw_mode();
        
            let msg = format!("{info}");
            _ = PANIC_MSG.set(Some(msg));
        
            hook(info)
        }));

        Self
    }
}

impl Default for PanicHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PanicHandler {
    fn drop(&mut self) {
        if let Some(msg) = PANIC_MSG.get().and_then(|x| x.as_ref()) {
            eprintln!("{msg}");
        }
    }
}