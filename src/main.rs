#![allow(unused_variables)]
#![allow(dead_code)]

extern crate inotify;
extern crate libc;
extern crate rand;
extern crate regex;
extern crate rustc_serialize;

use rand::*;
use std::io::ErrorKind;

mod askpass;
mod socket;
mod yubikey;

fn random_challenge() -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::new();
    for _ in 0..64 {
        vec.push(rand::random());
    }
    vec
}

fn yubikey_testing() -> Result<(), yubikey::YubikeyError> {
    yubikey::yubikey_init();

    let yk = try!(yubikey::get_yubikey());
    let challenge = &random_challenge();
    let result = try!(yubikey::challenge_response(yk, 2, challenge, false));

    println!("{}", result);
    Ok(())
}

fn main() {
    println!("Checking for existing systemd-asks");

    match askpass::check_existing_asks() {
        Ok(()) => println!("Done, exiting"),
        Err(ref e) if e.kind() == ErrorKind::Other => {
            println!("No existing asks. Monitoring ask folder.");
            askpass::watch_ask_loop(20)
        }
        Err(e) => panic!(e)
    }
}
