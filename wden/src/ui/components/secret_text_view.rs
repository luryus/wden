use cursive::{View, theme::Style, utils::span::SpannedString};
use zeroize::Zeroizing;

pub struct SecretTextView {
    content: Zeroizing<String>,
    hidden: bool,
    style: Style,
}

impl SecretTextView {
    pub fn new(content: String) -> Self {
        SecretTextView {
            content: Zeroizing::new(content),
            hidden: true,
            style: Style::none(),
        }
    }

    pub fn _hidden(mut self) -> Self {
        self.hidden = true;
        self
    }

    pub fn _visible(mut self) -> Self {
        self.hidden = false;
        self
    }

    pub fn style<S: Into<Style>>(mut self, style: S) -> Self {
        self.style = style.into();
        self
    }

    pub fn _set_hidden(&mut self, hidden: bool) {
        self.hidden = hidden;
    }

    pub fn toggle_hidden(&mut self) {
        self.hidden = !self.hidden;
    }
}

impl View for SecretTextView {
    fn draw(&self, printer: &cursive::Printer) {
        let styled = SpannedString::styled(
            if self.hidden {
                "*******"
            } else {
                &self.content
            },
            self.style,
        );
        printer.print_styled((0, 0), &styled);
    }
}
