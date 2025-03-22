use crate::platform::windows::{channel, OutOfBandMessage};
use crate::platform::OsIpcSharedMemory;
use windows::core::{Error, HRESULT, PCSTR};
use windows::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows::Win32::Storage::FileSystem::READ_CONTROL;
use windows::Win32::System::Memory::{CreateFileMappingA, PAGE_READWRITE};
use windows::Win32::System::Threading::{
    CreateEventA, GetCurrentProcess, GetCurrentProcessId, GetProcessId, OpenProcess,
    PROCESS_ACCESS_RIGHTS, PROCESS_DUP_HANDLE,
};

#[test]
fn test_recover_handles_empty() {
    let target_process_id = unsafe { GetCurrentProcessId() };
    let mut oob = OutOfBandMessage::new(target_process_id);
    assert!(oob.recover_handles().is_ok());
}

#[test]
fn test_recover_handles_duplicates_channel_handles() {
    let mut handles = Vec::new();

    // Create some dummy event handles
    for _ in 0..3 {
        let event =
            unsafe { CreateEventA(None, false, false, None) }.expect("Failed to create event");
        handles.push(event.0 as isize);
    }

    let mut oob = OutOfBandMessage {
        target_process_id: unsafe { GetCurrentProcessId() },
        channel_handles: handles.clone(),
        shmem_handles: vec![],
        big_data_receiver_handle: None,
    };

    let result = oob.recover_handles();

    assert!(result.is_ok());
    assert_eq!(oob.channel_handles.len(), 3);
    for (i, handle) in oob.channel_handles.iter().enumerate() {
        assert_ne!(*handle, handles[i]);
        assert_ne!(*handle as isize, INVALID_HANDLE_VALUE.0 as isize);
    }

    // Clean up the handles
    for handle in handles {
        unsafe { CloseHandle(HANDLE(handle as _)) }.expect("Failed to close handle");
    }
    for handle in oob.channel_handles {
        unsafe { CloseHandle(HANDLE(handle as _)) }.expect("Failed to close handle");
    }
}

#[test]
fn test_recover_handles_empty_channel_handles() {
    let mut oob = OutOfBandMessage {
        target_process_id: unsafe { GetCurrentProcessId() },
        channel_handles: vec![],
        shmem_handles: vec![],
        big_data_receiver_handle: None,
    };

    let result = oob.recover_handles();

    assert!(result.is_ok());
    assert_eq!(oob.channel_handles.len(), 0);
}

#[test]
fn test_recover_handles_duplicates_shmem_handles() {
    let mut handles = Vec::new();
    let mut sizes = Vec::new();

    // Create some dummy shared memory handles
    for _ in 0..3 {
        let file_mapping = unsafe {
            CreateFileMappingA(
                INVALID_HANDLE_VALUE,
                None,
                PAGE_READWRITE,
                0,
                1024,
                PCSTR::null(),
            )
        }
        .expect("Failed to create file mapping");
        handles.push(file_mapping.0 as isize);
        sizes.push(1024u64);
    }

    let mut oob = OutOfBandMessage {
        target_process_id: unsafe { GetCurrentProcessId() },
        channel_handles: vec![],
        shmem_handles: handles.clone().into_iter().zip(sizes.into_iter()).collect(),
        big_data_receiver_handle: None,
    };

    let result = oob.recover_handles();

    assert!(result.is_ok());
    assert_eq!(oob.shmem_handles.len(), 3);
    for (handle, size) in &oob.shmem_handles {
        assert_ne!(*handle, INVALID_HANDLE_VALUE.0 as isize);
        assert_eq!(*size, 1024);

        // Verify that the new handle is valid and different from the original
        let new_handle = HANDLE(*handle as _);
        assert!(unsafe { CompareObjectHandles(new_handle, INVALID_HANDLE_VALUE) } == false);

        // Clean up the duplicated handle
        unsafe { CloseHandle(new_handle) }.expect("Failed to close duplicated handle");
    }

    // Clean up the original handles
    for handle in handles.into_iter() {
        unsafe { CloseHandle(HANDLE(handle as _)) }.expect("Failed to close original handle");
    }
}

#[test]
fn test_recover_handles_empty_shmem_handles() {
    let mut oob = OutOfBandMessage {
        target_process_id: unsafe { GetCurrentProcessId() },
        channel_handles: vec![],
        shmem_handles: vec![],
        big_data_receiver_handle: None,
    };

    let result = oob.recover_handles();

    assert!(result.is_ok());
    assert!(oob.shmem_handles.is_empty());
}

#[test]
fn test_recover_handles_duplicates_big_data_receiver_handle() {
    let event = unsafe { CreateEventA(None, false, false, None) }.expect("Failed to create event");
    let event_handle = event.0 as isize;

    let mut oob = OutOfBandMessage {
        target_process_id: unsafe { GetCurrentProcessId() },
        channel_handles: vec![],
        shmem_handles: vec![],
        big_data_receiver_handle: Some((event_handle, 1024)),
    };

    let result = oob.recover_handles();

    assert!(result.is_ok());
    if let Some((handle, _)) = oob.big_data_receiver_handle {
        assert_ne!(handle, event_handle);
        unsafe {
            let new_handle = HANDLE(handle as _);
            assert!(CompareObjectHandles(event, new_handle).as_bool());
            CloseHandle(new_handle).expect("Failed to close duplicated handle");
        }
    } else {
        panic!("big_data_receiver_handle is None after recovery");
    }

    unsafe { CloseHandle(event).expect("Failed to close original event handle") };
}

#[test]
fn test_recover_handles_with_no_big_data_receiver() {
    let mut handles = Vec::new();

    // Create some dummy event handles
    for _ in 0..5 {
        let event =
            unsafe { CreateEventA(None, false, false, None) }.expect("Failed to create event");
        handles.push(event.0 as isize);
    }
    let mut oob = OutOfBandMessage {
        target_process_id: unsafe { GetCurrentProcessId() },
        channel_handles: vec![handles[0], handles[1], handles[2]],
        shmem_handles: vec![(handles[3], 100), (handles[4], 200)],
        big_data_receiver_handle: None,
    };

    let result = oob.recover_handles();

    assert!(result.is_ok());
    assert_eq!(oob.channel_handles.len(), 3);
    assert_eq!(oob.shmem_handles.len(), 2);
    assert!(oob.big_data_receiver_handle.is_none());

    // Verify that the handles have been duplicated (i.e., they're different from the original handles)
    for (i, handle) in oob.channel_handles.iter().enumerate() {
        assert_ne!(*handle, handles[i]);
    }
    for (i, (handle, _)) in oob.shmem_handles.iter().enumerate() {
        assert_ne!(*handle, handles[i + 3]);
    }

    // Clean up the original handles
    for handle in handles {
        unsafe { CloseHandle(HANDLE(handle as _)) }.expect("Failed to close handle");
    }
}

#[test]
fn test_recover_handles_fails_with_arbitrary_process_id() {
    let mut oob = OutOfBandMessage {
        target_process_id: 0, // Use 0 as an invalid process ID
        channel_handles: vec![],
        shmem_handles: vec![],
        big_data_receiver_handle: None,
    };

    let result = oob.recover_handles();

    assert!(result.is_err());
    // The exact error code might vary, but it should be an error
    assert!(result.unwrap_err().code() != HRESULT(0i32));
}

#[test]
fn test_recover_handles_fails_with_invalid_handles() {
    let mut handles = Vec::new();

    // Create some dummy event handles
    for _ in 0..3 {
        let event =
            unsafe { CreateEventA(None, false, false, None) }.expect("Failed to create event");
        handles.push(event.0 as isize);
    }

    let mut oob = OutOfBandMessage {
        target_process_id: unsafe { GetCurrentProcessId() },
        channel_handles: handles.clone(),
        shmem_handles: vec![],
        big_data_receiver_handle: None,
    };

    // Close the handles to make them invalid
    for handle in handles.clone().into_iter() {
        unsafe { CloseHandle(HANDLE(handle as _)).expect("Failed to close handle") };
    }

    // Now try to recover the handles
    let result = oob.recover_handles();

    // The recovery should fail because the handles are now invalid
    assert!(result.is_err());

    // Check that the error is of the expected type
    match result.unwrap_err() {
        err if err.code() == ERROR_INVALID_HANDLE.to_hresult() => {},
        err => panic!("Unexpected error: {:?}", err),
    }

    // Verify that the channel handles in oob are still the same (invalid) handles
    assert_eq!(oob.channel_handles, handles);
}

#[test]
fn test_recover_handles_large_number_of_handles() {
    let mut oob = OutOfBandMessage {
        target_process_id: unsafe { GetCurrentProcessId() },
        channel_handles: Vec::new(),
        shmem_handles: Vec::new(),
        big_data_receiver_handle: None,
    };

    const NUM_HANDLES: usize = 1000;

    // Create a large number of dummy event handles
    for _ in 0..NUM_HANDLES {
        let event =
            unsafe { CreateEventA(None, false, false, None) }.expect("Failed to create event");
        oob.channel_handles.push(event.0 as isize);
    }

    // Add some dummy shared memory handles
    for _ in 0..NUM_HANDLES {
        let mapping = unsafe {
            CreateFileMappingA(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, 4096, None)
        }
        .expect("Failed to create file mapping");
        oob.shmem_handles.push((mapping.0 as isize, 4096));
    }

    // Add a dummy big data receiver handle
    let big_data_event =
        unsafe { CreateEventA(None, false, false, None) }.expect("Failed to create big data event");
    oob.big_data_receiver_handle = Some((big_data_event.0 as isize, 8192));

    // Call recover_handles
    oob.recover_handles().expect("Failed to recover handles");

    // Verify that all handles were duplicated correctly
    for handle in &oob.channel_handles {
        assert_ne!(*handle, INVALID_HANDLE_VALUE.0 as isize);
        assert!(unsafe { CloseHandle(HANDLE(*handle as _)) }.is_ok());
    }

    for (handle, _) in &oob.shmem_handles {
        assert_ne!(*handle, INVALID_HANDLE_VALUE.0 as isize);
        assert!(unsafe { CloseHandle(HANDLE(*handle as _)) }.is_ok());
    }

    if let Some((handle, _)) = oob.big_data_receiver_handle {
        assert_ne!(handle, INVALID_HANDLE_VALUE.0 as isize);
        assert!(unsafe { CloseHandle(HANDLE(handle as _)) }.is_ok());
    }

    assert_eq!(oob.channel_handles.len(), NUM_HANDLES);
    assert_eq!(oob.shmem_handles.len(), NUM_HANDLES);
    assert!(oob.big_data_receiver_handle.is_some());
}

#[test]
fn test_recover_handles_channel() {
    let (sender, _) = channel().unwrap();
    let target_process_id = unsafe { GetCurrentProcessId() };
    let mut oob = OutOfBandMessage::new(target_process_id);

    oob.channel_handles.push(sender.handle.as_raw().0 as _);

    assert!(oob.recover_handles().is_ok());
    assert_eq!(oob.channel_handles.len(), 1);
    assert_ne!(oob.channel_handles[0], sender.handle.as_raw().0 as _);

    // Clean up
    unsafe { CloseHandle(HANDLE(oob.channel_handles[0] as _)).unwrap() };
}

#[test]
fn test_recover_handles_shmem() {
    let shmem = OsIpcSharedMemory::new(1024).unwrap();
    let target_process_id = unsafe { GetCurrentProcessId() };
    let mut oob = OutOfBandMessage::new(target_process_id);

    oob.shmem_handles.push((shmem.handle.as_raw().0 as _, 1024));

    assert!(oob.recover_handles().is_ok());
    assert_eq!(oob.shmem_handles.len(), 1);
    assert_ne!(oob.shmem_handles[0].0, shmem.handle.as_raw().0 as _);

    // Clean up
    unsafe { CloseHandle(HANDLE(oob.shmem_handles[0].0 as _)).unwrap() };
}

#[test]
fn test_recover_handles_invalid_process() {
    let mut oob = OutOfBandMessage::new(0); // Invalid process ID
    oob.channel_handles.push(1); // Dummy handle

    assert!(oob.recover_handles().is_err());
}
