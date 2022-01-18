use cursive::{CbSink, Cursive};

use crate::ui::data::UserData;

pub trait CursiveExt {
    fn clear_layers(&mut self);

    fn get_user_data(&mut self) -> &mut UserData;
}

impl CursiveExt for Cursive {
    fn clear_layers(&mut self) {
        while self.pop_layer().is_some() {}
    }

    fn get_user_data(&mut self) -> &mut UserData {
        self.user_data().expect("User data was not present")
    }
}

pub trait CursiveCallbackExt {
    fn send_msg(&self, f: Box<dyn FnOnce(&mut Cursive) + Send>);
}

impl CursiveCallbackExt for CbSink {
    fn send_msg(&self, f: Box<dyn FnOnce(&mut Cursive) + Send>) {
        self.send(f).expect("Sending cursive callback failed");
    }
}
