use cursive::{
    event::Event,
    views::{EditView, NamedView, OnEventView},
};

type Inner = NamedView<EditView>;

pub fn add_readline_shortcuts(edit: Inner) -> OnEventView<Inner> {
    let mut ev_view = OnEventView::new(edit);

    ev_view = handle_remove_word_back(ev_view);
    ev_view = handle_move_end(ev_view);
    ev_view = handle_move_start(ev_view);

    ev_view
}

fn handle_remove_word_back(ev_view: OnEventView<Inner>) -> OnEventView<Inner> {
    ev_view.on_event_inner(Event::CtrlChar('w'), |named, _| {
        // Remove word back from cursor
        let content = named.get_mut().get_content();
        if let Some(idx) = content.trim_end().rfind(char::is_whitespace) {
            named.get_mut().set_content(content.split_at(idx + 1).0);
        }

        None
    })
}

fn handle_move_start(ev_view: OnEventView<Inner>) -> OnEventView<Inner> {
    ev_view.on_event_inner(Event::CtrlChar('a'), |named, _| {
        // Move cursor to start
        named.get_mut().set_cursor(0);
        None
    })
}

fn handle_move_end(ev_view: OnEventView<Inner>) -> OnEventView<Inner> {
    ev_view.on_event_inner(Event::CtrlChar('e'), |named, _| {
        // Move cursor to end
        let mut edit = named.get_mut();
        let end_idx = edit.get_content().len();
        edit.set_cursor(end_idx);
        None
    })
}

fn handle_cut_to_end(ev_view: OnEventView<Inner>) -> OnEventView<Inner> {
    ev_view.on_event_inner(Event::CtrlChar('k'), |named, _| {
        let mut edit = named.get_mut();
        let idx = edit.
    })
}