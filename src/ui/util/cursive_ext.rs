use std::future::Future;

use cursive::{CbSink, Cursive};

use crate::ui::data::UserData;

pub trait CursiveExt {
    fn clear_layers(&mut self);

    fn get_user_data(&mut self) -> &mut UserData;

    fn async_op<A, B>(&mut self, a: A, b: B)
    where
        A: Future + Send + 'static,
        A::Output: Send + 'static,
        B: FnOnce(&mut Cursive, A::Output) + Send + 'static;
}

impl CursiveExt for Cursive {
    fn clear_layers(&mut self) {
        while self.pop_layer().is_some() {}
    }

    fn get_user_data(&mut self) -> &mut UserData {
        self.user_data().expect("User data was not present")
    }

    fn async_op<A, C>(&mut self, async_cb: A, cursive_cb: C)
    where
        A: Future + Send + 'static,
        A::Output: Send + 'static,
        C: FnOnce(&mut Cursive, A::Output) + Send + 'static,
    {
        let cb = self.cb_sink().clone();
        tokio::spawn(async move {
            let res = async_cb.await;
            cb.send_msg(Box::new(|siv| cursive_cb(siv, res)))
        });
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
