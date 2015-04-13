/* Implements a systemd password agent as per
http://www.freedesktop.org/wiki/Software/systemd/PasswordAgents/ */

use inotify::INotify;
use inotify::ffi::*;
use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::{Read, Result, Error, ErrorKind};
use std::path::Path;
use std::thread::sleep_ms;
use regex::Regex;

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

    match stem {
        Some(s) if s == ask_name => handle_ask(filepath),
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
                let full_path = format!("{}/{}", SYSTEMD_ASK_PATH, event.name);
                let filepath = Path::new(&full_path);
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
fn handle_ask(filepath: &Path) -> bool {
    let mut is_pw_ask = false;

    match fs::File::open(filepath) {
        Err(e)   => println!("{}", e),
        Ok(mut file) => match parse_ask(&mut file, &mut is_pw_ask) {
            Ok(_)  => println!("Responded successfully"),
            Err(e) => println!("{}", e)
        }
    }

    is_pw_ask
}

fn parse_ask(file: &mut File, is_pw_ask: &mut bool) -> Result<()> {
    let challenge = get_challenge();

    let mut file_content = String::new();
    try!(file.read_to_string(&mut file_content));

    if file_content.contains(SYSTEMD_ASK_MSG) {
        *is_pw_ask = true;
        match capture_socket(&file_content) {
            None => Ok(()),
            Some(socket) => handle_respond(challenge, &socket)
        }
    } else {
        Ok(())
    }

    // NYI: kill(PID, 0) -> if ESRCH ignore file (this is in the spec)
    // Currently the only kill() in Rust is deprecated so I'm gonna wait
}

#[doc = "Extracts Socket address from an ask file using regexes. An unsafe
function is being used because the safe alternative is not marked as stable
yet. Rust ensures that content is not mutable in the context of this function."]
fn capture_socket(content: &str) -> Option<String> {
    let sock_reg = Regex::new(r"(?m)^Socket=(.*)$").unwrap();
    match sock_reg.find(&content) {
        None => None,
        Some((start, end)) => {
            let socket =
                unsafe { content.slice_unchecked(start + 7, end).to_string() };
            Some(socket)
        }
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
