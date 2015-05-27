use libc::{c_int, c_uint, uint8_t};
use rustc_serialize::hex::ToHex;
use std::error::Error;
use std::fmt;
use std::io;

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

/*****************************
 *  Safe interface to ykpers *
 *****************************/

#[derive(Debug)]
pub enum YubikeyError { InvalidYubikeySlot,
                        NoYubikeyConnected,
                        EmptyCRChallenge,
                        OtherError(io::Error) }

impl Error for YubikeyError {
    fn description(&self) -> &str {
        match *self {
            YubikeyError::InvalidYubikeySlot => "The selected Yubikey slot is invalid. Valid are 1, 2",
            YubikeyError::NoYubikeyConnected => "No Yubikey connected",
            YubikeyError::EmptyCRChallenge   => "The specified challenge was empty",
            YubikeyError::OtherError(ref e)  => e.description()
        }
    }
}

impl fmt::Display for YubikeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(self.description())
    }
}

/// Internal function used to retrieve and wrap the last error from libykpers
fn last_yk_error() -> YubikeyError {
    YubikeyError::OtherError(io::Error::last_os_error())
}

/// Opaque pointer to foreign Yubikey type. Under the hood this is just a handle
/// for a USB device.
pub struct Yubikey {
    /// Foreign pointer to the USB handle
    yk: *const YK_KEY
}

/* When a Yubikey goes out of scope, close the handle */
impl Drop for Yubikey {
    fn drop(&mut self) {
        unsafe { yk_close_key(self.yk) };
    }
}

impl Yubikey {
    /// Connects to the first available Yubikey
    pub fn get_yubikey() -> Result<Yubikey, YubikeyError> {
        unsafe { yk_init() };
        let yk = unsafe { yk_open_first_key() };
        if yk.is_null() { // Probably no Yubikey connected
            Err(YubikeyError::NoYubikeyConnected)
        } else {
            Ok(Yubikey{ yk: yk })
        }
    }

    /// Returns the serial number of the Yubikey
    pub fn get_serial(&self) -> Result<u32, YubikeyError> {
        unsafe {
            let mut serial: c_uint = 0;
            match yk_get_serial(self.yk, 0, 0, &mut serial) {
                0 => Err(last_yk_error()),
                _ => Ok(serial as u32)
            }
        }
    }

    /// Handles a HMAC-SHA1 challenge-response interaction with a Yubikey.
    ///
    /// # Examples
    ///
    /// ```
    /// use yubikey::Yubikey;
    ///
    /// let yk = try!(Yubikey::get_yubikey());
    /// yk.challenge_response(&some_byte_slice, false)
    /// ```
    ///
    /// # Failures
    ///
    /// This function can fail in several different ways at a lower level, in
    /// which case the exact error is returned as a `YubikeyError`.
    /// This could be unrecoverable errors such as unplugged Yubikeys.
    pub fn challenge_response(&self, slot: u8, challenge: &[u8],
                              may_block: bool) -> Result<String, YubikeyError> {
        // Yubikey commands are defined in ykdef.h
        let yk_cmd = try!(match slot {
            1 => Ok(0x30), //#define SLOT_CHAL_HMAC1 0x30
            2 => Ok(0x38), //#define SLOT_CHAL_HMAC2 0x38
            _ => Err(YubikeyError::InvalidYubikeySlot)
        });

        let challenge_len = challenge.len() as c_uint;

        if challenge_len == 0 {
            return Err(YubikeyError::EmptyCRChallenge);
        }

        let response_len = 64; // Length of HMAC-SHA1 response

        let mut response = Vec::with_capacity(response_len as usize);

        let rc = unsafe {
            let cr_status =
                yk_challenge_response(self.yk, yk_cmd, may_block as c_int,
                                      challenge_len, challenge.as_ptr(),
                                      response_len, response.as_mut_ptr());

            response.set_len(response_len as usize);
            cr_status
        };

        if rc == 0 {
            Err(last_yk_error())
        } else {
            let mut response_str = (&mut response).to_hex();
            response_str.truncate(40);
            Ok(response_str)
        }
    }
}
