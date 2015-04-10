/* Rust doesn't have unix datagram socket support at the moment. Hope I can ditch
 * this in the future.
 * Thanks to @gcourier for his rust-syslog library which I used as a reference. */

use std::os::unix::io::RawFd;
use std::mem;
use std::io::{Result, Error, ErrorKind};
use std::ffi::CString;
use libc;

fn construct_sockaddr(path: &CString) -> Result<(libc::sockaddr_storage, usize)> {
    assert!(mem::size_of::<libc::sockaddr_storage>() >=
            mem::size_of::<libc::sockaddr_un>());

    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let s: &mut libc::sockaddr_un = unsafe { mem::transmute(&mut storage) };

    let len = path.as_bytes().len();
    if len > s.sun_path.len() - 1 {
        let err = Error::new(ErrorKind::InvalidInput,
                             "Socket path can not be longer than sizeof(sockaddr_storage) - 1");
        return Err(err);
    }

    s.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, value) in s.sun_path.iter_mut().zip(path.as_bytes().iter()) {
        *slot = *value as i8;
    }

    let len = mem::size_of::<libc::sa_family_t>() + len + 1;

    return Ok((storage, len));
}


fn unix_socket(ty: libc::c_int) -> Result<RawFd> {
    match unsafe { libc::socket(libc::AF_UNIX, ty, 0) } {
        -1 => Err(Error::last_os_error()),
        fd => Ok(fd)
    }
}

pub struct UnixSocket {
    fd: RawFd,
}

impl UnixSocket {
    pub fn new() -> Result<UnixSocket> {
        match unsafe {
            libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0)
        } {
            -1 => Err(Error::last_os_error()),
            fd => Ok(UnixSocket{fd: fd})
        }
    }

    pub fn sendto(&mut self, buf: &[u8], path: &CString) -> Result<()> {
        let (dst, len) = try!(construct_sockaddr(path));
        let dstp = &dst as *const libc::sockaddr_storage;
        let ret = unsafe { libc::sendto(self.fd,
                                        buf.as_ptr() as *const libc::c_void,
                                        buf.len() as libc::size_t,
                                        0x4000, // MSG_NOSIGNAL
                                        dstp as *const libc::sockaddr,
                                        len as libc::socklen_t) as libc::c_int };

        match ret {
            -1 => Err(Error::last_os_error()),
            n if n as usize != buf.len() =>
                Err(Error::new(ErrorKind::Other, "Could not send entire package")),
            _ => Ok(())
        }
    }
}
