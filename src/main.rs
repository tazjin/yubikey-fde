#![allow(unused_variables)]
#![allow(dead_code)]

extern crate inotify;
extern crate libc;
extern crate regex;
extern crate rustc_serialize;

use std::io::ErrorKind;

mod askpass;
mod socket;
mod yubikey;

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
