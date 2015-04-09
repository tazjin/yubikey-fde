#![feature(libc)]
#![feature(rand)]
#![feature(core)]
#![feature(convert)]
#![feature(as_slice)]
#![feature(collections)]

extern crate libc;
extern crate rustc_serialize;

use rustc_serialize::hex::ToHex;
use std::rand;

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
    let challenge = b"testtest";
    //let challenge = random_challenge();
    
    match yubikey::challenge_response(yk, 2, challenge.as_slice(), false) {
        Err(_)       => println!("error occured"),
        Ok(result) => println!("{}", result)
    }
}
