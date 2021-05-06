// use std::ops::{
//     Deref,
//     DerefMut,
// };
use std::os::unix::io::{
    AsRawFd,
    RawFd,
    IntoRawFd,
    FromRawFd,
};
use std::fmt;
use std::cmp::{PartialEq};
use std::mem;
use std::fs::File;
use std::cell::RefCell;

pub struct OwnedFd(RefCell<RawFd>);

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if *self.0.borrow() != -1 {
            unsafe {
                let _ = libc::close(*self.0.borrow());
            }
        }
    }
}

// impl Deref for OwnedFd {
//     type Target = RawFd;

//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

// impl DerefMut for OwnedFd {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.0
//     }
// }

impl IntoRawFd for OwnedFd {
    fn into_raw_fd(self) -> RawFd {
        let fd = *self.0.borrow();
        mem::forget(self);
        fd
    }
}

impl AsRawFd for OwnedFd {
    fn as_raw_fd(& self) -> RawFd {
        *self.0.borrow()
    }
}

impl FromRawFd for OwnedFd {
    unsafe fn from_raw_fd(fd: RawFd) -> OwnedFd {
        OwnedFd::new(fd)
    }
}

impl Into<File> for OwnedFd {
    fn into(self) -> File {
        unsafe {
            File::from_raw_fd(self.into_raw_fd())
        }
    }
}

impl From<File> for OwnedFd {
    fn from(file: File) -> Self {
        OwnedFd::new(file.into_raw_fd())
    }
}

impl OwnedFd {
    pub fn new(fd: RawFd) -> OwnedFd {
        OwnedFd(RefCell::new(fd))
    }

    pub fn consume(&self) -> OwnedFd {
        let fd = self.0.replace(-1);
        OwnedFd::new(fd)
    }
}

impl PartialEq for OwnedFd {
    fn eq(&self, other: &Self) -> bool {
        *self.0.borrow() == *other.0.borrow()
    }
}

impl fmt::Debug for OwnedFd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("")
         .field(&self.0)
         .finish()
    }
}
