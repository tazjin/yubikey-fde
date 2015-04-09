#![allow(unused_variables)]
#![allow(dead_code)]

extern crate inotify;
extern crate libc;
extern crate rand;
extern crate rustc_serialize;

use rand::*;

mod askpass;
mod yubikey;

fn random_challenge() -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::new();
    for _ in 0..64 {
        vec.push(rand::random());
    }
    vec
}

fn main() {
    yubikey::yubikey_init();
    let yk = yubikey::get_yubikey();

    let challenge = &random_challenge();

    match yubikey::challenge_response(yk, 2, challenge, false) {
        Err(_)     => println!("error occured"),
        Ok(result) => println!("{}", result)
    }
}
