use libc::{c_int, c_uint, uint8_t, c_char};
use std::slice;
use std::ptr;
use rustc_serialize::hex::ToHex;
use std::fmt::Error;

#[repr(C)]
struct YK_KEY;

#[link(name="ykpers-1")]
extern {
    fn yk_init() -> c_int;
    fn yk_open_first_key() -> *const YK_KEY;
    fn yk_close_key(yk: *const YK_KEY) -> c_int;
    fn yk_get_serial(yk: *const YK_KEY, slot: uint8_t, flags: c_uint,
                     serial: *mut c_uint) -> c_int;
    fn yk_challenge_response(yk: *const YK_KEY, yk_cmd: uint8_t, may_block: c_int,
                             challenge_len: c_uint, challenge: *const uint8_t,
                             response_len: c_uint, response: *mut u8) -> c_int;
}

/* When a YK_KEY goes out of scope, close the handle */
impl Drop for YK_KEY {
    fn drop(&mut self) {
        unsafe { yk_close_key(self) };
    }
}

/*****************************
*  Safe interface to ykpers  *
*****************************/

pub enum YubikeyError { InvalidYubikeySlot,
                        EmptyCRChallenge,
                        UnknownError }

/* Opaque pointer to foreign Yubikey type. Under the hood this is just a handle
*  for a USB device. */
pub type Yubikey = *const YK_KEY;

/* This function must be called at least once before using any of the Yubikey
*  functionality. It initializes the Yubikey C library. */
pub fn yubikey_init() {
    unsafe { yk_init() };
}

/* Returns the first plugged in Yubikey. */
pub fn get_yubikey() -> Yubikey {
    unsafe { yk_open_first_key() }
}

/* Returns the serial number of the Yubikey */
pub fn get_serial(yk: Yubikey) -> u32 {
    unsafe {
        let mut serial: c_uint = 0;
        yk_get_serial(yk, 0, 0, &mut serial);
        serial as u32
    }
}


//#define SLOT_CHAL_HMAC1		0x30	/* Write 64 byte challenge to slot 1, get HMAC-SHA1 response */
//#define SLOT_CHAL_HMAC2		0x38	/* Write 64 byte challenge to slot 2, get HMAC-SHA1 response */


pub fn challenge_response(yk: Yubikey, slot: u8, challenge: &[u8], may_block: bool) -> Result<String, YubikeyError> {
    // Yubikey commands are defined in ykdef.h
    let yk_cmd = try!(match slot {
        1 => Ok(0x30), //#define SLOT_CHAL_HMAC1 0x30
        2 => Ok(0x38), //#define SLOT_CHAL_HMAC2 0x38
        _ => Err(YubikeyError::InvalidYubikeySlot)
    });

    let challenge_len = challenge.len() as c_uint;

    if (challenge_len == 0) {
        return Err(YubikeyError::EmptyCRChallenge);
    }
    
    let response_len = 64; // Length of HMAC-SHA1 response

    let mut response = Vec::with_capacity(response_len as usize);
    let mut cr_status = 0; // Return code to check *after* unsafe block

    unsafe {
        cr_status = yk_challenge_response(yk, yk_cmd, may_block as c_int,
                                          challenge_len, challenge.as_ptr(),
                                          response_len, response.as_mut_ptr());

        response.set_len(response_len as usize);
    }

    if (cr_status == 0) {
        // There's some way to get a better error code from the Yubikey, but
        // that's not needed right now.
        Err(YubikeyError::UnknownError)
    } else {
        // There must be a better way to do this, but I'm not sure what it is yet
        let response_str =
            String::from_str(response.as_slice().to_hex().as_str().slice_chars(0,40));
        Ok(response_str)
    }
}
