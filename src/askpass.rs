/* Implements a systemd password agent as per
http://www.freedesktop.org/wiki/Software/systemd/PasswordAgents/ */

use ini::Ini;
use inotify::INotify;
use inotify::ffi::*;
use inotify::wrapper::Event;
use std::ffi::CString;
use std::io::Result;
use std::path::Path;
use std::thread::sleep_ms;

use socket;
use yubikey;

const SYSTEMD_ASK_PATH: &'static str = "/run/systemd/ask-password";
const SYSTEMD_ASK_MSG: &'static str = "Please enter passphrase for disk";

#[doc = "Watch systemd's ask password folder for incoming requests."]
#[allow(unused_must_use)]
pub fn watch_ask_loop(mut timeout: u8) {
    let mut ino = INotify::init().unwrap();
    ino.add_watch(Path::new(SYSTEMD_ASK_PATH), IN_CLOSE_WRITE | IN_MOVED_TO).unwrap();

    'outer: loop {
        if timeout <= 0 {
            // Why do these types mismatch in inotify-rs?
            ino.rm_watch((IN_CLOSE_WRITE | IN_MOVED_TO) as i32);
            break;
        }

        let events = ino.available_events().unwrap();
        for event in events.iter() {
            if event.name.starts_with("ask.") {
                if handle_ask(event) {
                    break 'outer;
                }
            }
        }

        timeout -= 1;
        sleep_ms(1000);
    }
}

fn get_challenge() -> &'static [u8] {
    b"testtest"
}

#[doc = "Handles an incoming inotify event. The return value does not indicate
success or failure, rather it indicates whether or not the event was a disk
decryption password request."]
fn handle_ask(event: &Event) -> bool {
    let filepath = format!("{}/{}", SYSTEMD_ASK_PATH, event.name);
    println!("Reading file {}", filepath);

    // We need to know the Message to check if this ask is for a disk password
    // and also what socket to send our response to.
    let mut ask = Ini::load_from_file(&filepath).unwrap();
    ask.begin_section("Ask");
    let ask_message = ask.get("Message").unwrap().to_string();
    let socket_path = ask.get("Socket").unwrap();
    let challenge = get_challenge();

    if ask_message.starts_with(SYSTEMD_ASK_MSG) {
        // NYI: kill(PID, 0) -> if ESRCH ignore file (this is in the spec)
        // Currently the only kill() in Rust is deprecated so I'm gonna wait

        let result = handle_respond(challenge, socket_path);
        match result {
            Ok(_)  => println!("Responded successfully"),
            Err(e) => panic!("{}", e)
        }

        return true;
    }

    return false;
}

fn handle_respond(challenge: &[u8], socket_path: &str) -> Result<()> {
    yubikey::yubikey_init();
    let yk = yubikey::get_yubikey().unwrap();
    let yk_response = yubikey::challenge_response(yk, 2, &challenge, false).unwrap();
    let response = format!("+{}", yk_response);
    let path_cstr = CString::new(socket_path).unwrap();
    let mut socket = try!(socket::UnixSocket::new());
    socket.sendto(&response.as_bytes(), &path_cstr)
}
