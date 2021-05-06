use std::mem;
use std::thread;
// use std::ops::{Deref, DerefMut};
use std::os::windows::io::{
     AsRawHandle,
     RawHandle,
     IntoRawHandle,
     FromRawHandle,
};
use std::fs::File;
use std::ffi::CString;
use std::default::Default;
use std::cell::{RefCell};

use winapi::um::winnt::{HANDLE};
use winapi::um::handleapi::{INVALID_HANDLE_VALUE};

use super::{WinError, CURRENT_PROCESS_HANDLE};

#[derive(Debug)]
pub struct WinHandle {
    h: RefCell<HANDLE>,
}

unsafe impl Send for WinHandle { }
unsafe impl Sync for WinHandle { }

impl Drop for WinHandle {
    fn drop(&mut self) {
        unsafe {
            if self.is_valid() {
                let result = winapi::um::handleapi::CloseHandle(*self.h.borrow());
                assert!(thread::panicking() || result != 0);
            }
        }
    }
}

impl Default for WinHandle {
    fn default() -> WinHandle {
        WinHandle { h: RefCell::new(INVALID_HANDLE_VALUE) }
    }
}

// impl Deref for WinHandle {
//     type Target = WinHandle;

//     fn deref(&self) -> &Self::Target {
//         &self.h
//     }
// }

// impl DerefMut for WinHandle {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.h
//     }
// }

impl IntoRawHandle for WinHandle {
    fn into_raw_handle(self) -> RawHandle {
        let handle = *self.h.borrow();
        mem::forget(self);
        handle
    }
}

impl AsRawHandle for WinHandle {
    fn as_raw_handle(& self) -> RawHandle {
        *self.h.borrow()
    }
}

impl FromRawHandle for WinHandle {
    unsafe fn from_raw_handle(handle: RawHandle) -> WinHandle {
        WinHandle::new(handle)
    }
}

impl Into<File> for WinHandle {
    fn into(self) -> File {
        unsafe {
            File::from_raw_handle(self.into_raw_handle())
        }
    }
}

impl From<File> for WinHandle {
    fn from(file: File) -> Self {
        WinHandle::new(file.into_raw_handle())
    }
}

const WINDOWS_APP_MODULE_NAME: &'static str = "api-ms-win-core-handle-l1-1-0";
const COMPARE_OBJECT_HANDLES_FUNCTION_NAME: &'static str = "CompareObjectHandles";

lazy_static! {
    static ref WINDOWS_APP_MODULE_NAME_CSTRING: CString = CString::new(WINDOWS_APP_MODULE_NAME).unwrap();
    static ref COMPARE_OBJECT_HANDLES_FUNCTION_NAME_CSTRING: CString = CString::new(COMPARE_OBJECT_HANDLES_FUNCTION_NAME).unwrap();
}

#[cfg(feature = "windows-shared-memory-equality")]
impl PartialEq for WinHandle {
    fn eq(&self, other: &WinHandle) -> bool {
        unsafe {
            // Calling LoadLibraryA every time seems to be ok since libraries are refcounted and multiple calls won't produce multiple instances.
            let module_handle = winapi::um::libloaderapi::LoadLibraryA(WINDOWS_APP_MODULE_NAME_CSTRING.as_ptr());
            if module_handle.is_null() {
                panic!("Error loading library {}. {}", WINDOWS_APP_MODULE_NAME, WinError::error_string(GetLastError()));
            }
            let proc = winapi::um::libloaderapi::GetProcAddress(module_handle, COMPARE_OBJECT_HANDLES_FUNCTION_NAME_CSTRING.as_ptr());
            if proc.is_null() {
                panic!("Error calling GetProcAddress to use {}. {}", COMPARE_OBJECT_HANDLES_FUNCTION_NAME, WinError::error_string(GetLastError()));
            }
            let compare_object_handles: unsafe extern "stdcall" fn(HANDLE, HANDLE) -> winapi::shared::minwindef::BOOL = std::mem::transmute(proc);
            compare_object_handles(self.h, other.h) != 0
        }
    }
}

impl WinHandle {
    pub fn new(h: HANDLE) -> WinHandle {
        WinHandle { h: RefCell::new(h) }
    }

    pub fn invalid() -> WinHandle {
        WinHandle { h: RefCell::new(INVALID_HANDLE_VALUE) }
    }

    pub fn is_valid(&self) -> bool {
        *self.h.borrow() != INVALID_HANDLE_VALUE
    }

    pub(crate) fn as_raw(&self) -> HANDLE {
        *self.h.borrow()
    }

    pub(crate) fn take_raw(&mut self) -> HANDLE {
        self.h.replace(INVALID_HANDLE_VALUE)
    }

    pub(crate) fn take(&mut self) -> WinHandle {
        WinHandle::new(self.take_raw())
    }

    pub(crate) fn consume(&self) -> WinHandle {
        WinHandle::new(self.h.replace(INVALID_HANDLE_VALUE))
    }
}

/// Duplicate a given handle from this process to the target one, passing the
/// given flags to DuplicateHandle.
///
/// Unlike win32 DuplicateHandle, this will preserve INVALID_HANDLE_VALUE (which is
/// also the pseudohandle for the current process).
pub fn dup_handle_to_process_with_flags(handle: &WinHandle, other_process: &WinHandle, flags: winapi::shared::minwindef::DWORD)
                                           -> Result<WinHandle, WinError>
{
    if !handle.is_valid() {
        return Ok(WinHandle::invalid());
    }

    unsafe {
        let mut new_handle: HANDLE = INVALID_HANDLE_VALUE;
        let ok = winapi::um::handleapi::DuplicateHandle(CURRENT_PROCESS_HANDLE.as_raw(), handle.as_raw(),
                                           other_process.as_raw(), &mut new_handle,
                                           0, winapi::shared::minwindef::FALSE, flags);
        if ok == winapi::shared::minwindef::FALSE {
            Err(WinError::last("DuplicateHandle"))
        } else {
            Ok(WinHandle::new(new_handle))
        }
    }
}

/// Duplicate a handle in the current process.
pub fn dup_handle(handle: &WinHandle) -> Result<WinHandle,WinError> {
    dup_handle_to_process(handle, &WinHandle::new(CURRENT_PROCESS_HANDLE.as_raw()))
}

/// Duplicate a handle to the target process.
pub fn dup_handle_to_process(handle: &WinHandle, other_process: &WinHandle) -> Result<WinHandle,WinError> {
    dup_handle_to_process_with_flags(handle, other_process, winapi::um::winnt::DUPLICATE_SAME_ACCESS)
}

/// Duplicate a handle to the target process, closing the source handle.
pub fn move_handle_to_process(handle: WinHandle, other_process: &WinHandle) -> Result<WinHandle,WinError> {
    let result = dup_handle_to_process_with_flags(&handle, other_process,
                                                  winapi::um::winnt::DUPLICATE_CLOSE_SOURCE | winapi::um::winnt::DUPLICATE_SAME_ACCESS);
    // Since the handle was moved to another process, the original is no longer valid;
    // so we probably shouldn't try to close it explicitly?
    mem::forget(handle);
    result
}