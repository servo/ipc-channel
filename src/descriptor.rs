use std::cell::RefCell;
use std::default::Default;
use std::fs::File;
use std::io;
use std::mem;
use std::thread;

#[cfg(windows)]
pub use {
    std::os::windows::io::RawHandle as RawDescriptor,
    std::os::windows::io::AsRawHandle,
    std::os::windows::io::IntoRawHandle,
    std::os::windows::io::FromRawHandle,
};

#[cfg(unix)]
pub use {
    std::os::unix::io::RawFd as RawDescriptor,
    std::os::unix::io::AsRawFd,
    std::os::unix::io::IntoRawFd,
    std::os::unix::io::FromRawFd,
};

#[cfg(windows)]
const INVALID_RAW_DESCRIPTOR: RawDescriptor = winapi::um::handleapi::INVALID_HANDLE_VALUE;

#[cfg(windows)]
fn raw_descriptor_close(descriptor: &RawDescriptor) -> Result<(), io::Error> {
    unsafe {
        let result = winapi::um::handleapi::CloseHandle(*descriptor);
        if result == 0 {
            Err(io::Error::last_os_error())
        }
        else {
            Ok(())
        }
    }
}

#[cfg(unix)]
const INVALID_RAW_DESCRIPTOR: RawDescriptor = -1;

#[cfg(unix)]
fn raw_descriptor_close(descriptor: &RawDescriptor) -> Result<(), io::Error> {
    unsafe {
        let result = libc::close(*descriptor);
        if result == 0 {
            Ok(())
        }
        else {
            Err(io::Error::last_os_error())
        }
    }
}

#[derive(Debug)]
pub struct OwnedDescriptor(RefCell<RawDescriptor>);

unsafe impl Send for OwnedDescriptor { }
unsafe impl Sync for OwnedDescriptor { }

impl Drop for OwnedDescriptor {
    fn drop(&mut self) {
        if *self.0.borrow() != INVALID_RAW_DESCRIPTOR {
            let result = raw_descriptor_close(&*self.0.borrow());
            assert!( thread::panicking() || result.is_ok() );
        }
    }
}

impl OwnedDescriptor {
    pub fn new(descriptor: RawDescriptor) -> OwnedDescriptor {
        OwnedDescriptor(RefCell::new(descriptor))
    }

    pub fn consume(& self) -> OwnedDescriptor {
        OwnedDescriptor::new(self.0.replace(INVALID_RAW_DESCRIPTOR))
    }
}

impl Default for OwnedDescriptor {
    fn default() -> OwnedDescriptor {
        OwnedDescriptor::new(INVALID_RAW_DESCRIPTOR)
    }
}

#[cfg(windows)]
impl IntoRawHandle for OwnedDescriptor {
    fn into_raw_handle(self) -> RawDescriptor {
        let handle = *self.0.borrow();
        mem::forget(self);
        handle
    }
}

#[cfg(windows)]
impl AsRawHandle for OwnedDescriptor {
    fn as_raw_handle(& self) -> RawDescriptor {
        *self.0.borrow()
    }
}

#[cfg(windows)]
impl FromRawHandle for OwnedDescriptor {
    unsafe fn from_raw_handle(handle: RawDescriptor) -> OwnedDescriptor {
        OwnedDescriptor::new(handle)
    }
}

#[cfg(windows)]
impl Into<File> for OwnedDescriptor {
    fn into(self) -> File {
        unsafe {
            File::from_raw_handle(self.into_raw_handle())
        }
    }
}

#[cfg(windows)]
impl From<File> for OwnedDescriptor {
    fn from(file: File) -> Self {
        OwnedDescriptor::new(file.into_raw_handle())
    }
}

const WINDOWS_APP_MODULE_NAME: &'static str = "api-ms-win-core-handle-l1-1-0";
const COMPARE_OBJECT_HANDLES_FUNCTION_NAME: &'static str = "CompareObjectHandles";

lazy_static! {
    static ref WINDOWS_APP_MODULE_NAME_CSTRING: std::ffi::CString = std::ffi::CString::new(WINDOWS_APP_MODULE_NAME).unwrap();
    static ref COMPARE_OBJECT_HANDLES_FUNCTION_NAME_CSTRING: std::ffi::CString = std::ffi::CString::new(COMPARE_OBJECT_HANDLES_FUNCTION_NAME).unwrap();
}

#[cfg(feature = "windows-shared-memory-equality")]
impl PartialEq for OwnedDescriptor {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            // Calling LoadLibraryA every time seems to be ok since libraries are refcounted and multiple calls won't produce multiple instances.
            let module_handle = winapi::um::libloaderapi::LoadLibraryA(WINDOWS_APP_MODULE_NAME_CSTRING.as_ptr());
            if module_handle.is_null() {
                panic!("Error loading library {}. {}", WINDOWS_APP_MODULE_NAME, std::io::Error::last_os_error());
            }
            let proc = winapi::um::libloaderapi::GetProcAddress(module_handle, COMPARE_OBJECT_HANDLES_FUNCTION_NAME_CSTRING.as_ptr());
            if proc.is_null() {
                panic!("Error calling GetProcAddress to use {}. {}", COMPARE_OBJECT_HANDLES_FUNCTION_NAME, std::io::Error::last_os_error());
            }
            let compare_object_handles: unsafe extern "stdcall" fn(RawDescriptor, RawDescriptor) -> winapi::shared::minwindef::BOOL = std::mem::transmute(proc);
            compare_object_handles(*self.0.borrow(), *other.0.borrow()) != 0
        }
    }
}

#[cfg(unix)]
impl IntoRawFd for OwnedDescriptor {
    fn into_raw_fd(self) -> RawDescriptor {
        let fd = self.0.replace(INVALID_RAW_DESCRIPTOR);
        mem::forget(self);
        fd 
    }
}

#[cfg(unix)]
impl AsRawFd for OwnedDescriptor {
    fn as_raw_fd(& self) -> RawDescriptor {
        *self.0.borrow()
    }
}

#[cfg(unix)]
impl FromRawFd for OwnedDescriptor {
    unsafe fn from_raw_fd(fd: RawDescriptor) -> OwnedDescriptor {
        OwnedDescriptor::new(fd)
    }
}

#[cfg(unix)]
impl Into<File> for OwnedDescriptor {
    fn into(self) -> File {
        unsafe {
            File::from_raw_fd(self.into_raw_fd())
        }
    }
}

#[cfg(unix)]
impl From<File> for OwnedDescriptor {
    fn from(file: File) -> Self {
        OwnedDescriptor::new(file.into_raw_fd())
    }
}

#[cfg(unix)]
impl PartialEq for OwnedDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
