/* Implements a systemd password agent as per
http://www.freedesktop.org/wiki/Software/systemd/PasswordAgents/ */

use inotify::INotify;
use inotify::wrapper::Event;
use inotify::ffi::*;
use std::path::Path;
use std::thread::sleep_ms;

#[doc = "Watch systemd's ask password folder for incoming requests."]
pub fn watch_ask_loop(mut timeout: u8) {
    let mut ino = INotify::init().unwrap();
    ino.add_watch(Path::new("/run/systemd/ask-password"), IN_CLOSE_WRITE | IN_MOVED_TO).unwrap();

    loop {
        if timeout <= 0 {
            // Why do these types mismatch in inotify-rs?
            ino.rm_watch((IN_CLOSE_WRITE | IN_MOVED_TO) as i32).unwrap();
            break;
        }

        let events = ino.available_events().unwrap();
        for event in events.iter() {
            if event.name.starts_with("ask.") {
                handle_ask(event);
            }
        }

        timeout -= 1;
        sleep_ms(1000);
    }
}

fn handle_ask(event: &Event) {
    println!("Received event for {}", event.name);
}
