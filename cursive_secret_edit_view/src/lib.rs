// Forked from cursive_core's EditView

/*
Copyright (c) 2015 Alexandre Bury

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and
to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
*/

mod zeroized_array_string;

use cursive_core::{
    direction::Direction,
    event::{Callback, Event, EventResult, Key, MouseEvent},
    immut2, impl_enabled,
    theme::{Effect, PaletteStyle, StyleType},
    utils::lines::simple::{simple_prefix, simple_suffix},
    view::CannotFocus,
    Cursive, Printer, Rect, Vec2, View, With,
};
use std::cell::RefCell;
use std::rc::Rc;
use unicode_segmentation::UnicodeSegmentation;
use zeroize::Zeroizing;

use self::zeroized_array_string::ZeroizedArrayString;


/// Closure type for callbacks when the content is modified.
///
/// Arguments are the `Cursive`, and current cursor position
pub type OnEdit = dyn Fn(&mut Cursive, usize);

/// Closure type for callbacks when Enter is pressed.
///
/// Arguments are the `Cursive`.
pub type OnSubmit = dyn Fn(&mut Cursive);

pub struct SecretEditView {
    /// Current content.
    content: Zeroizing<ZeroizedArrayString<256>>,

    /// Cursor position in the content, in bytes.
    cursor: usize,

    /// Number of bytes to skip at the beginning of the content.
    ///
    /// (When the content is too long for the display, we hide part of it)
    offset: usize,

    /// Last display length, to know the possible offset range
    last_length: usize,

    /// Callback when the content is modified.
    ///
    /// Will be called with the current content and the cursor position.
    on_edit: Option<Rc<OnEdit>>,

    /// Callback when `<Enter>` is pressed.
    on_submit: Option<Rc<OnSubmit>>,

    /// Character to fill empty space
    filler: String,

    enabled: bool,

    style: StyleType,
}

impl Default for SecretEditView {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretEditView {
    impl_enabled!(self.enabled);

    /// Creates a new, empty edit view.
    pub fn new() -> Self {
        SecretEditView {
            content: Zeroizing::new(ZeroizedArrayString::new()),
            cursor: 0,
            offset: 0,
            last_length: 0, // scrollable: false,
            on_edit: None,
            on_submit: None,
            filler: "_".to_string(),
            enabled: true,
            style: PaletteStyle::Secondary.into(),
        }
    }

    /// Sets the style used for this view.
    ///
    /// When the view is enabled, the style will be reversed.
    ///
    /// Defaults to `ColorStyle::Secondary`.
    pub fn set_style<S: Into<StyleType>>(&mut self, style: S) {
        self.style = style.into();
    }

    /// Sets the style used for this view.
    ///
    /// When the view is enabled, the style will be reversed.
    ///
    /// Chainable variant.
    #[must_use]
    pub fn style<S: Into<StyleType>>(self, style: S) -> Self {
        self.with(|s| s.set_style(style))
    }

    /// Sets a mutable callback to be called whenever the content is modified.
    ///
    /// `callback` will be called with the view
    /// content and the current cursor position.
    ///
    /// *Warning*: this callback cannot be called recursively. If you somehow
    /// trigger this callback again in the given closure, it will be ignored.
    ///
    /// If you don't need a mutable closure but want the possibility of
    /// recursive calls, see [`set_on_edit`](#method.set_on_edit).
    pub fn set_on_edit_mut<F>(&mut self, callback: F)
    where
        F: FnMut(&mut Cursive, usize) + 'static,
    {
        self.set_on_edit(immut2!(callback));
    }

    /// Sets a callback to be called whenever the content is modified.
    ///
    /// `callback` will be called with the view
    /// content and the current cursor position.
    ///
    /// This callback can safely trigger itself recursively if needed
    /// (for instance if you call `on_event` on this view from the callback).
    ///
    /// If you need a mutable closure and don't care about the recursive
    /// aspect, see [`set_on_edit_mut`](#method.set_on_edit_mut).
    pub fn set_on_edit<F>(&mut self, callback: F)
    where
        F: Fn(&mut Cursive, usize) + 'static,
    {
        self.on_edit = Some(Rc::new(callback));
    }

    /// Sets a mutable callback to be called whenever the content is modified.
    ///
    /// Chainable variant. See [`set_on_edit_mut`](#method.set_on_edit_mut).
    #[must_use]
    pub fn on_edit_mut<F>(self, callback: F) -> Self
    where
        F: FnMut(&mut Cursive, usize) + 'static,
    {
        self.with(|v| v.set_on_edit_mut(callback))
    }

    /// Sets a callback to be called whenever the content is modified.
    ///
    /// Chainable variant. See [`set_on_edit`](#method.set_on_edit).
    #[must_use]
    pub fn on_edit<F>(self, callback: F) -> Self
    where
        F: Fn(&mut Cursive, usize) + 'static,
    {
        self.with(|v| v.set_on_edit(callback))
    }

    /// Sets a mutable callback to be called when `<Enter>` is pressed.
    ///
    /// `callback` will be given the content of the view.
    ///
    /// *Warning*: this callback cannot be called recursively. If you somehow
    /// trigger this callback again in the given closure, it will be ignored.
    ///
    /// If you don't need a mutable closure but want the possibility of
    /// recursive calls, see [`set_on_submit`](#method.set_on_submit).
    pub fn set_on_submit_mut<F>(&mut self, callback: F)
    where
        F: FnMut(&mut Cursive) + 'static,
    {
        // TODO: don't duplicate all those methods.
        // Instead, have some generic function immutify()
        // or something that wraps a FnMut closure.
        let callback = RefCell::new(callback);
        self.set_on_submit(move |s| {
            if let Ok(mut f) = callback.try_borrow_mut() {
                (*f)(s);
            }
        });
    }

    /// Sets a callback to be called when `<Enter>` is pressed.
    ///
    /// `callback` will be given the content of the view.
    ///
    /// This callback can safely trigger itself recursively if needed
    /// (for instance if you call `on_event` on this view from the callback).
    ///
    /// If you need a mutable closure and don't care about the recursive
    /// aspect, see [`set_on_submit_mut`](#method.set_on_submit_mut).
    pub fn set_on_submit<F>(&mut self, callback: F)
    where
        F: Fn(&mut Cursive) + 'static,
    {
        self.on_submit = Some(Rc::new(callback));
    }

    /// Sets a mutable callback to be called when `<Enter>` is pressed.
    ///
    /// Chainable variant.
    #[must_use]
    pub fn on_submit_mut<F>(self, callback: F) -> Self
    where
        F: FnMut(&mut Cursive) + 'static,
    {
        self.with(|v| v.set_on_submit_mut(callback))
    }

    /// Sets a callback to be called when `<Enter>` is pressed.
    ///
    /// Chainable variant.
    #[must_use]
    pub fn on_submit<F>(self, callback: F) -> Self
    where
        F: Fn(&mut Cursive) + 'static,
    {
        self.with(|v| v.set_on_submit(callback))
    }

    /// Replace the entire content of the view with the given one.
    ///
    /// Returns a callback in response to content change.
    ///
    /// You should run this callback with a `&mut Cursive`.
    pub fn set_content<S: Into<Zeroizing<String>>>(&mut self, content: S) -> Callback {
        let content = content.into();
        let len = content.len();

        if len > self.content.0.capacity() {
            return Callback::dummy();
        }

        self.content.0.clear();
        self.content.0.push_str(&content);

        self.offset = 0;
        self.set_cursor(len);

        self.make_edit_cb().unwrap_or_else(Callback::dummy)
    }

    /// Get the current text.
    pub fn get_content(&self) -> &str {
        &self.content.0
    }

    /// Sets the current content to the given value.
    ///
    /// Convenient chainable method.
    ///
    /// Does not run the `on_edit` callback.
    #[must_use]
    pub fn content<S: Into<Zeroizing<String>>>(mut self, content: S) -> Self {
        self.set_content(content);
        self
    }

    /// Sets the cursor position.
    pub fn set_cursor(&mut self, cursor: usize) {
        assert!(cursor <= self.content.0.len());
        self.cursor = cursor;

        self.keep_cursor_in_view();
    }

    /// Insert `ch` at the current cursor position.
    ///
    /// Returns a callback in response to content change.
    ///
    /// You should run this callback with a `&mut Cursive`.
    pub fn insert(&mut self, ch: char) -> Callback {
        // First, make sure we can actually insert anything.
        if ch.len_utf8() > self.content.0.remaining_capacity() {
            return Callback::dummy();
        }

        self.content.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();

        self.keep_cursor_in_view();

        self.make_edit_cb().unwrap_or_else(Callback::dummy)
    }

    /// Remove the character at the current cursor position.
    ///
    /// Returns a callback in response to content change.
    ///
    /// You should run this callback with a `&mut Cursive`.
    pub fn remove(&mut self) -> Callback {
        self.content.0.remove(self.cursor);

        self.keep_cursor_in_view();

        self.make_edit_cb().unwrap_or_else(Callback::dummy)
    }

    fn make_edit_cb(&self) -> Option<Callback> {
        self.on_edit.clone().map(|cb| {
            // Get a new Rc on the content
            let cursor = self.cursor;

            Callback::from_fn(move |s| {
                cb(s, cursor);
            })
        })
    }

    fn keep_cursor_in_view(&mut self) {
        // keep cursor in [offset, offset+last_length] by changing offset
        // so keep offset in [last_length-cursor,cursor]
        // Also call this on resize,
        // but right now it is an event like any other
        if self.cursor < self.offset {
            self.offset = self.cursor;
        } else {
            // So we're against the right wall.
            // Let's find how much space will be taken by the selection
            // (either a char, or _)
            let c_len = 1;

            // Now, we have to fit self.content[..self.cursor]
            // into self.last_length - c_len.
            let available = match self.last_length.checked_sub(c_len) {
                Some(s) => s,
                // Weird - no available space?
                None => return,
            };
            // Look at the content before the cursor (we will print its tail).
            // From the end, count the length until we reach `available`.
            // Then sum the byte lengths.

            let suffix_length =
                simple_suffix(&self.content.0[self.offset..self.cursor], available).length;

            assert!(suffix_length <= self.cursor);
            self.offset = self.cursor - suffix_length;
            // Make sure the cursor is in view
            assert!(self.cursor >= self.offset);
        }

        // If we have too much space
        if self.content.0.len() - self.offset < self.last_length {
            assert!(self.last_length >= 1);
            let suffix_length = simple_suffix(&self.content.0, self.last_length - 1).length;

            assert!(self.content.0.len() >= suffix_length);
            self.offset = self.content.0.len() - suffix_length;
        }
    }
}

impl View for SecretEditView {
    fn draw(&self, printer: &Printer) {
        assert_eq!(
            printer.size.x, self.last_length,
            "Was promised {}, received {}",
            self.last_length, printer.size.x
        );

        let width = self.content.0.graphemes(true).count();
        printer.with_style(self.style, |printer| {
            let effect = if self.enabled && printer.enabled {
                Effect::Reverse
            } else {
                Effect::Simple
            };
            printer.with_effect(effect, |printer| {
                if width < self.last_length {
                    // No problem, everything fits.
                    assert!(printer.size.x >= width);
                    printer.print_hline((0usize, 0), width, "*");
                    let filler_len = printer.size.x - width;
                    printer.print_hline((width, 0), filler_len, self.filler.as_str());
                } else {
                    let width = self.content.0[self.offset..].graphemes(true).count()
                        .min(self.last_length);
                    printer.print_hline((0usize, 0), width, "*");
                    
                    if width < self.last_length {
                        let filler_len = self.last_length - width;
                        printer.print_hline(
                            (width, 0),
                            filler_len,
                            self.filler.as_str(),
                        );
                    }
                }
            });

            // Now print cursor
            if printer.focused {
                let c: &str = if self.cursor == self.content.0.len() {
                    &self.filler
                } else {
                    "*"
                };
                let offset = self.content.0[self.offset..self.cursor]
                    .graphemes(true)
                    .count();
                printer.print((offset, 0), c);
            }
        });
    }

    fn layout(&mut self, size: Vec2) {
        self.last_length = size.x;
    }

    fn take_focus(&mut self, _: Direction) -> Result<EventResult, CannotFocus> {
        self.enabled.then(EventResult::consumed).ok_or(CannotFocus)
    }

    fn on_event(&mut self, event: Event) -> EventResult {
        if !self.enabled {
            return EventResult::Ignored;
        }
        match event {
            Event::Char(ch) => {
                return EventResult::Consumed(Some(self.insert(ch)));
            }
            // TODO: handle ctrl-key?
            Event::Key(Key::Home) => self.set_cursor(0),
            Event::Key(Key::End) => {
                // When possible, NLL to the rescue!
                let len = self.content.0.len();
                self.set_cursor(len);
            }
            Event::Key(Key::Left) if self.cursor > 0 => {
                let len = self.content.0[..self.cursor]
                    .graphemes(true)
                    .last()
                    .unwrap()
                    .len();
                let cursor = self.cursor - len;
                self.set_cursor(cursor);
            }
            Event::Key(Key::Right) if self.cursor < self.content.0.len() => {
                let len = self.content.0[self.cursor..]
                    .graphemes(true)
                    .next()
                    .unwrap()
                    .len();
                let cursor = self.cursor + len;
                self.set_cursor(cursor);
            }
            Event::Key(Key::Backspace) if self.cursor > 0 => {
                let len = self.content.0[..self.cursor]
                    .graphemes(true)
                    .last()
                    .unwrap()
                    .len();
                self.cursor -= len;
                return EventResult::Consumed(Some(self.remove()));
            }
            Event::Key(Key::Del) if self.cursor < self.content.0.len() => {
                return EventResult::Consumed(Some(self.remove()));
            }
            Event::Key(Key::Enter) if self.on_submit.is_some() => {
                let cb = self.on_submit.clone().unwrap();
                return EventResult::with_cb(move |s| {
                    cb(s);
                });
            }
            Event::Mouse {
                event: MouseEvent::Press(_),
                position,
                offset,
            } if position.fits_in_rect(offset, (self.last_length, 1)) => {
                if let Some(position) = position.checked_sub(offset) {
                    self.cursor = self.offset
                        + simple_prefix(&self.content.0[self.offset..], position.x).length;
                }
            }
            _ => return EventResult::Ignored,
        }

        // self.keep_cursor_in_view();

        EventResult::Consumed(Some(Callback::dummy()))
    }

    fn important_area(&self, _: Vec2) -> Rect {
        let char_width = 1;

        let x = self.cursor;

        Rect::from_size((x, 0), (char_width, 1))
    }
}
