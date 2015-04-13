/* Implements a systemd password agent as per
http://www.freedesktop.org/wiki/Software/systemd/PasswordAgents/ */

use ini::Ini;
use inotify::INotify;
use inotify::ffi::*;
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{Result, Error, ErrorKind};
use std::path::Path;
use std::thread::sleep_ms;

use socket;
use yubikey;

const SYSTEMD_ASK_PATH: &'static str = "/run/systemd/ask-password";
const SYSTEMD_ASK_MSG: &'static str = "Please enter passphrase for disk";

#[doc = "Check for existing ask requests before starting the watch loop"]
pub fn check_existing_asks() -> Result<()> {
    let ask_dir = Path::new(SYSTEMD_ASK_PATH);
    //    if ask_dir.is_dir() {} // This isn't stable yet
    for entry in try!(fs::read_dir(ask_dir)) {
        let entry = try!(entry);
        let entry_path =  entry.path();
        if handle_existing(entry_path.as_path()) {
            return Ok(())
        }
    }

    return Err(Error::new(ErrorKind::Other, "No existing asks found"));
}

#[doc = "Checks whether an existing file has the correct prefix before dispatching.
Return value indicates whether an event was handled or not."]
fn handle_existing(filepath: &Path) -> bool {
    let ask_name = OsStr::new("ask");
    let stem = filepath.file_stem();
    let filename = filepath.to_string_lossy().to_string();

    match stem {
        Some(s) if s == ask_name => handle_ask(&filename),
        _ => false
    }
}

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
                let filepath = format!("{}/{}", SYSTEMD_ASK_PATH, event.name);
                if handle_ask(&filepath) {
                    break 'outer;
                }
            }
        }

        timeout -= 1;
        sleep_ms(1000);
    }
}

fn get_challenge() -> &'static [u8] {
    b"iCaiyoosashohm5yeiRi"
}

#[doc = "Handles an incoming inotify event. The return value does not indicate
success or failure, rather it indicates whether or not the event was a disk
decryption password request."]
fn handle_ask(filepath: &String) -> bool {
    let mut is_pw_ask = false;

    match Ini::load_from_file(&filepath) {
        Err(e)      => println!("{}", e),
        Ok(mut ask) => match parse_event(&mut ask, &mut is_pw_ask) {
            Ok(_)  => println!("Responded successfully"),
            Err(e) => println!("{}", e)
        }
    }

    is_pw_ask
}

fn parse_event(ask: &mut Ini, is_pw_ask: &mut bool) -> Result<()> {
    ask.begin_section("Ask");
    let ask_message = ask.get("Message").unwrap();
    let socket_path = ask.get("Socket").unwrap();
    let challenge = get_challenge();

    // NYI: kill(PID, 0) -> if ESRCH ignore file (this is in the spec)
    // Currently the only kill() in Rust is deprecated so I'm gonna wait
    if ask_message.to_string().starts_with(SYSTEMD_ASK_MSG) {
        *is_pw_ask = true;
        handle_respond(challenge, socket_path)
    } else {
        Ok(())
    }

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
