use cursive::CbSink;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::interval;

use super::lock::lock_vault;
use super::util::cursive_ext::CursiveCallbackExt;

pub struct Autolocker {
    next_lock_time: Option<Instant>,
    autolock_time: Duration,
}

pub fn start_autolocker(cb_sink: CbSink, autolock_time: Duration) -> Arc<Mutex<Autolocker>> {
    let next_autolock_time = Arc::new(Mutex::new(Autolocker {
        next_lock_time: None,
        autolock_time,
    }));

    tokio::spawn(autolock_loop(cb_sink, Arc::clone(&next_autolock_time)));

    next_autolock_time
}

impl Autolocker {
    pub fn update_next_autolock_time(&mut self, enable_lock: bool) {
        if self.next_lock_time.is_some() || enable_lock {
            self.next_lock_time = Some(Instant::now() + self.autolock_time);
        }
    }

    pub fn clear_autolock_time(&mut self) {
        self.next_lock_time = None;
    }
}

async fn autolock_loop(cb_sink: CbSink, next_autolock_time: Arc<Mutex<Autolocker>>) {
    let mut int = interval(Duration::from_secs(10));

    loop {
        int.tick().await;

        if let Some(t) = next_autolock_time.lock().unwrap().next_lock_time
            && Instant::now() > t
        {
            cb_sink.send_msg(Box::new(lock_vault));
        }
    }
}
