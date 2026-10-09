use super::mach_sys::{
    self, mach_msg_guarded_port_descriptor_t, mach_msg_header_t, mach_msg_ool_descriptor_t,
    mach_msg_ool_ports_descriptor_t, mach_msg_port_descriptor_t, mach_port_t,
};
use super::{
    allocate_vm_pages, channel, destroy_message, mach_port_allocate, mach_port_mod_release,
    mach_task_self, mark_regions_for_deallocation, parse_message, read_at, MachError, Message,
    OsIpcOneShotServer, OsIpcSender, OsIpcSharedMemory, ReceivedPayload, KERN_SUCCESS,
    MACH_MSGH_BITS_COMPLEX, MACH_MSG_GUARDED_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR,
    MACH_MSG_OOL_PORTS_DESCRIPTOR, MACH_MSG_OOL_VOLATILE_DESCRIPTOR, MACH_MSG_PORT_DESCRIPTOR,
    MACH_MSG_SUCCESS, MACH_MSG_TIMEOUT_NONE, MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND,
    MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_VIRTUAL_COPY, MACH_PORT_NULL, MACH_PORT_RIGHT_RECEIVE,
    MACH_PORT_RIGHT_SEND, MACH_SEND_MSG,
};
use std::{mem, ptr, slice};

const HEADER_SIZE: usize = mem::size_of::<mach_msg_header_t>();
const MACH_MSG_PHYSICAL_COPY: u32 = 0;
const VM_FLAGS_ANYWHERE: i32 = 1;

/// The bytes of an integer or of a Mach struct without padding.
fn as_bytes<T>(value: &T) -> &[u8] {
    // SAFETY: callers pass types whose bytes are all initialized.
    unsafe { slice::from_raw_parts(value as *const T as *const u8, mem::size_of::<T>()) }
}

/// `bytes`, copied into a buffer aligned for a message header.
fn aligned(bytes: &[u8]) -> Vec<u64> {
    let mut buffer = vec![0u64; bytes.len().div_ceil(8)];
    // SAFETY: `buffer` holds at least `bytes.len()` bytes.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.as_mut_ptr() as *mut u8, bytes.len())
    };
    buffer
}

/// A message assembled field by field in the layout `OsIpcSender::send`
/// writes, so that tests can make it malformed.
struct RawMessage {
    bits: u32,
    /// Everything after the header, starting with the descriptor count.
    body: Vec<u8>,
}

impl RawMessage {
    fn new(complex: bool, descriptor_count: u32) -> RawMessage {
        let bits = if complex { MACH_MSGH_BITS_COMPLEX } else { 0 };
        RawMessage {
            bits,
            body: Vec::new(),
        }
        .push(&descriptor_count)
    }

    /// Appends the bytes of `value`, whose type must have no padding.
    fn push<T>(mut self, value: &T) -> RawMessage {
        self.body.extend_from_slice(as_bytes(value));
        self
    }

    fn guarded_port(self, name: mach_port_t) -> RawMessage {
        // SAFETY: an all-zero descriptor is valid.
        let mut descriptor: mach_msg_guarded_port_descriptor_t = unsafe { mem::zeroed() };
        descriptor.name = name;
        descriptor.set_type(MACH_MSG_GUARDED_PORT_DESCRIPTOR);
        self.push(&descriptor)
    }

    fn port(self, name: mach_port_t, disposition: u32) -> RawMessage {
        // SAFETY: an all-zero descriptor is valid.
        let mut descriptor: mach_msg_port_descriptor_t = unsafe { mem::zeroed() };
        descriptor.name = name;
        descriptor.set_disposition(disposition);
        descriptor.set_type(MACH_MSG_PORT_DESCRIPTOR);
        self.push(&descriptor)
    }

    /// Appends an out-of-line descriptor; `type_` may also be the volatile or
    /// the ports variant, which share its layout.
    fn region_with(self, address: *mut u8, size: usize, type_: u32, copy: u32) -> RawMessage {
        // SAFETY: an all-zero descriptor is valid.
        let mut descriptor: mach_msg_ool_descriptor_t = unsafe { mem::zeroed() };
        descriptor.address = address as *mut _;
        descriptor.size = size as u32;
        descriptor.set_copy(copy);
        descriptor.set_type(type_);
        self.push(&descriptor)
    }

    fn region(self, address: *mut u8, size: usize) -> RawMessage {
        self.region_with(
            address,
            size,
            MACH_MSG_OOL_DESCRIPTOR,
            MACH_MSG_VIRTUAL_COPY,
        )
    }

    /// The descriptor points at `names`, which must stay alive while the
    /// message is in use.
    fn port_array(self, names: &[mach_port_t], disposition: u32) -> RawMessage {
        // SAFETY: an all-zero descriptor is valid.
        let mut descriptor: mach_msg_ool_ports_descriptor_t = unsafe { mem::zeroed() };
        descriptor.address = names.as_ptr() as *mut _;
        descriptor.count = names.len() as u32;
        descriptor.set_copy(MACH_MSG_VIRTUAL_COPY);
        descriptor.set_disposition(disposition);
        descriptor.set_type(MACH_MSG_OOL_PORTS_DESCRIPTOR);
        self.push(&descriptor)
    }

    /// Appends the inline data flag and, if `flag` is not zero, a payload
    /// whose size field says `declared_size`.
    fn payload(mut self, flag: u8, declared_size: usize, data: &[u8]) -> RawMessage {
        self = self.push(&flag);
        if flag == 0 {
            return self;
        }
        while (HEADER_SIZE + self.body.len()) % 8 != 0 {
            self = self.push(&0u8);
        }
        self = self.push(&declared_size);
        self.body.extend_from_slice(data);
        self
    }

    fn inline_payload(self, data: &[u8]) -> RawMessage {
        self.payload(1, data.len(), data)
    }

    fn out_of_line_payload(self) -> RawMessage {
        self.payload(0, 0, &[])
    }

    /// The header followed by the body, padded to a multiple of four bytes.
    fn bytes(&self, remote_port: mach_port_t) -> Vec<u8> {
        let size = (HEADER_SIZE + self.body.len()).next_multiple_of(4);
        let header = mach_msg_header_t {
            msgh_bits: MACH_MSG_TYPE_COPY_SEND as u32 | self.bits,
            msgh_size: size as u32,
            msgh_remote_port: remote_port,
            msgh_local_port: MACH_PORT_NULL,
            msgh_voucher_port: MACH_PORT_NULL,
            msgh_id: 0,
        };
        let mut bytes = as_bytes(&header).to_vec();
        bytes.extend_from_slice(&self.body);
        bytes.resize(size, 0);
        bytes
    }

    /// Sends the message to `port`, the name of a send right.
    fn send(&self, port: mach_port_t) {
        let bytes = self.bytes(port);
        let mut buffer = aligned(&bytes);
        // SAFETY: `buffer` holds the message and is aligned for the header.
        let result = unsafe {
            mach_sys::mach_msg(
                buffer.as_mut_ptr() as *mut mach_msg_header_t,
                MACH_SEND_MSG,
                bytes.len() as u32,
                0,
                MACH_PORT_NULL,
                MACH_MSG_TIMEOUT_NONE,
                MACH_PORT_NULL,
            )
        };
        assert_eq!(result, MACH_MSG_SUCCESS);
    }
}

fn send_refs(name: mach_port_t) -> u32 {
    let mut refs = 0;
    // SAFETY: a plain kernel call with a valid out pointer.
    let result = unsafe {
        mach_sys::mach_port_get_refs(mach_task_self(), name, MACH_PORT_RIGHT_SEND, &mut refs)
    };
    assert_eq!(result, KERN_SUCCESS);
    refs
}

/// `SIZE` bytes of this task's memory, filled with a known byte.
struct Page(*mut u8);

impl Page {
    const SIZE: usize = 4096;
    const FILL: u8 = 0xa5;

    fn new() -> Page {
        // SAFETY: `allocate_vm_pages` returns `SIZE` writable bytes.
        unsafe {
            let address = allocate_vm_pages(Page::SIZE);
            ptr::write_bytes(address, Page::FILL, Page::SIZE);
            Page(address)
        }
    }

    fn is_intact(&self) -> bool {
        // SAFETY: the memory is mapped unless the code under test freed it;
        // then this faults or reads whatever was mapped there since, and the
        // test fails.
        unsafe { slice::from_raw_parts(self.0, Page::SIZE) }
            .iter()
            .all(|byte| *byte == Page::FILL)
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        // SAFETY: deallocates the page allocated in `new`.
        let result =
            unsafe { mach_sys::vm_deallocate(mach_task_self(), self.0 as usize, Page::SIZE) };
        assert_eq!(result, KERN_SUCCESS);
    }
}

/// `VM_MEMORY_APPLICATION_SPECIFIC_11`, a tag that nothing else here allocates
/// with, so that `is_tagged_mapping` is not fooled by another mapping at a
/// freed address.
const TEST_VM_TAG: u32 = 250;

fn allocate_tagged(size: usize) -> *mut u8 {
    let mut address = 0;
    // `VM_MAKE_TAG` puts the tag in the top byte of the flags.
    let flags = VM_FLAGS_ANYWHERE | (TEST_VM_TAG << 24) as i32;
    // SAFETY: a plain kernel call with a valid out pointer.
    let result = unsafe { mach_sys::vm_allocate(mach_task_self(), &mut address, size, flags) };
    assert_eq!(result, KERN_SUCCESS);
    address as *mut u8
}

/// Whether `address` is still mapped by an `allocate_tagged` allocation.
fn is_tagged_mapping(address: *mut u8) -> bool {
    let address = address as usize;
    let (mut region, mut size, mut depth) = (address, 0, 0);
    // SAFETY: an all-zero struct of integers is valid.
    let mut info: mach_sys::vm_region_submap_info_64 = unsafe { mem::zeroed() };
    let mut count = (mem::size_of_val(&info) / mem::size_of::<i32>()) as u32;
    // SAFETY: a plain kernel call with valid out pointers and `info`'s size.
    let result = unsafe {
        mach_sys::vm_region_recurse_64(
            mach_task_self(),
            &mut region,
            &mut size,
            &mut depth,
            &mut info as *mut _ as mach_sys::vm_region_recurse_info_t,
            &mut count,
        )
    };
    let user_tag = info.user_tag;
    result == KERN_SUCCESS
        && region <= address
        && address < region + size
        && user_tag == TEST_VM_TAG
}

/// Asserts that the out-of-line descriptors from `offset` in a marked message
/// have the `deallocate` bit set and the given types.
fn assert_marked_regions(message: &[u8], offset: usize, types: &[u32]) {
    for (index, &type_) in types.iter().enumerate() {
        let at = offset + index * mem::size_of::<mach_msg_ool_descriptor_t>();
        // SAFETY: the descriptor is made of integers and a raw pointer.
        let region: mach_msg_ool_descriptor_t = unsafe { read_at(message, at) }.unwrap();
        assert_eq!(region.deallocate(), 1);
        assert_eq!(region.type_(), type_);
    }
}

#[test]
fn one_shot_server_rejects_a_simple_message_that_claims_a_region() {
    let (server, name) = OsIpcOneShotServer::new().unwrap();
    let sender = OsIpcSender::connect(name).unwrap();
    let page = Page::new();
    // The kernel does not translate the body of a simple message, so this
    // "descriptor" is plain data naming an address in the receiver.
    RawMessage::new(false, 1)
        .region(page.0, Page::SIZE)
        .out_of_line_payload()
        .send(sender.port);

    let result = server.accept();

    assert_eq!(result.err(), Some(MachError::RcvMalformedMessage));
    assert!(page.is_intact());
}

#[test]
fn receiver_destroys_a_message_with_a_port_after_a_region() {
    let (sender, receiver) = channel().unwrap();
    let port = mach_port_allocate(MACH_PORT_RIGHT_RECEIVE).unwrap();
    let page = Page::new();
    RawMessage::new(true, 2)
        .region(page.0, Page::SIZE)
        .port(port, MACH_MSG_TYPE_MAKE_SEND as u32)
        .inline_payload(&[])
        .send(sender.port);

    let result = receiver.recv();

    assert_eq!(result.err(), Some(MachError::RcvMalformedMessage));
    assert_eq!(send_refs(port), 0);
    sender.send(b"still open", vec![], vec![]).unwrap();
    assert_eq!(receiver.recv().unwrap().data, b"still open");
    mach_port_mod_release(port, MACH_PORT_RIGHT_RECEIVE).unwrap();
}

#[test]
fn receiver_destroys_a_message_with_an_array_of_ports() {
    let (sender, receiver) = channel().unwrap();
    let port = mach_port_allocate(MACH_PORT_RIGHT_RECEIVE).unwrap();
    RawMessage::new(true, 1)
        .port_array(&[port, port], MACH_MSG_TYPE_MAKE_SEND as u32)
        .inline_payload(&[])
        .send(sender.port);

    let result = receiver.recv();

    assert_eq!(result.err(), Some(MachError::RcvMalformedMessage));
    assert_eq!(send_refs(port), 0);
    mach_port_mod_release(port, MACH_PORT_RIGHT_RECEIVE).unwrap();
}

#[test]
fn receiver_rejects_an_inline_payload_that_runs_past_the_message() {
    let (sender, receiver) = channel().unwrap();
    // The payload would end in the trailer, which is in the receive buffer but
    // past the message.
    RawMessage::new(true, 0)
        .payload(1, 10, b"hi")
        .send(sender.port);

    assert_eq!(receiver.recv().err(), Some(MachError::RcvMalformedMessage));
}

#[test]
fn destroying_a_message_frees_every_kind_of_region() {
    const SIZE: usize = 16384;
    let physical = allocate_tagged(SIZE);
    let volatile = allocate_tagged(SIZE);
    let port_array = allocate_tagged(SIZE);
    // SAFETY: the memory is zero-filled, so it holds null port names.
    let names = unsafe {
        slice::from_raw_parts(
            port_array as *const mach_port_t,
            SIZE / mem::size_of::<mach_port_t>(),
        )
    };
    let bytes = RawMessage::new(true, 4)
        .guarded_port(MACH_PORT_NULL)
        .region_with(
            physical,
            SIZE,
            MACH_MSG_OOL_DESCRIPTOR,
            MACH_MSG_PHYSICAL_COPY,
        )
        .region_with(
            volatile,
            SIZE,
            MACH_MSG_OOL_VOLATILE_DESCRIPTOR,
            MACH_MSG_VIRTUAL_COPY,
        )
        .port_array(names, MACH_MSG_TYPE_MOVE_SEND)
        .inline_payload(&[])
        .bytes(MACH_PORT_NULL);
    for address in [physical, volatile, port_array] {
        assert!(is_tagged_mapping(address), "{address:?} not found");
    }
    // A walk that went wrong would make `destroy_message` free the wrong
    // memory, so check the marking first.
    let mut marked = bytes.clone();
    assert_eq!(mark_regions_for_deallocation(&mut marked), Some(()));
    assert_marked_regions(
        &marked,
        mem::size_of::<Message>() + mem::size_of::<mach_msg_guarded_port_descriptor_t>(),
        &[
            MACH_MSG_OOL_DESCRIPTOR,
            MACH_MSG_OOL_DESCRIPTOR,
            MACH_MSG_OOL_PORTS_DESCRIPTOR,
        ],
    );
    let mut buffer = aligned(&bytes);

    // SAFETY: like a message the kernel delivered, this one carries only null
    // names and memory that this task owns and does not use again.
    unsafe {
        destroy_message(slice::from_raw_parts_mut(
            buffer.as_mut_ptr() as *mut u8,
            bytes.len(),
        ))
    };

    for address in [physical, volatile, port_array] {
        assert!(!is_tagged_mapping(address), "{address:?} still mapped");
    }
}

#[test]
fn every_region_is_marked_for_deallocation() {
    let mut bytes = RawMessage::new(true, 5)
        .port(7, 0)
        .guarded_port(8)
        .region_with(
            0x1000 as *mut u8,
            16,
            MACH_MSG_OOL_DESCRIPTOR,
            MACH_MSG_PHYSICAL_COPY,
        )
        .region_with(
            0x2000 as *mut u8,
            16,
            MACH_MSG_OOL_VOLATILE_DESCRIPTOR,
            MACH_MSG_VIRTUAL_COPY,
        )
        .port_array(&[7], 0)
        .inline_payload(b"hi")
        .bytes(MACH_PORT_NULL);
    let original = bytes.clone();

    let result = mark_regions_for_deallocation(&mut bytes);

    assert_eq!(result, Some(()));
    let first_region = mem::size_of::<Message>()
        + mem::size_of::<mach_msg_port_descriptor_t>()
        + mem::size_of::<mach_msg_guarded_port_descriptor_t>();
    assert_eq!(bytes[..first_region], original[..first_region]);
    let expected_types = [
        MACH_MSG_OOL_DESCRIPTOR,
        MACH_MSG_OOL_DESCRIPTOR,
        MACH_MSG_OOL_PORTS_DESCRIPTOR,
    ];
    assert_marked_regions(&bytes, first_region, &expected_types);
    let regions_end =
        first_region + expected_types.len() * mem::size_of::<mach_msg_ool_descriptor_t>();
    assert_eq!(bytes[regions_end..], original[regions_end..]);
}

#[test]
fn receiver_accepts_a_hand_built_well_formed_message() {
    let (sender, receiver) = channel().unwrap();
    RawMessage::new(true, 0)
        .inline_payload(b"hello")
        .send(sender.port);

    assert_eq!(receiver.recv().unwrap().data, b"hello");
}

#[test]
fn receiver_accepts_an_empty_out_of_line_payload() {
    let (sender, receiver) = channel().unwrap();
    RawMessage::new(true, 1)
        .region(ptr::null_mut(), 0)
        .out_of_line_payload()
        .send(sender.port);

    assert!(receiver.recv().unwrap().data.is_empty());
}

#[test]
fn receiver_hands_over_an_empty_region_as_an_empty_slice() {
    let (sender, receiver) = channel().unwrap();
    RawMessage::new(true, 1)
        .region(ptr::null_mut(), 0)
        .inline_payload(b"hi")
        .send(sender.port);

    let mut message = receiver.recv().unwrap();
    let region = &mut message.os_ipc_shared_memory_regions[0];

    assert!(region.ptr.is_null());
    assert!(region.is_empty());
    // SAFETY: nothing else refers to the region.
    assert!(unsafe { region.deref_mut() }.is_empty());
}

#[test]
fn an_allocated_empty_region_is_an_empty_slice() {
    let mut region = OsIpcSharedMemory::from_bytes(&[]);

    assert!(region.ptr.is_null());
    assert!(region.is_empty());
    assert!(region.clone().is_empty());
    // SAFETY: nothing else refers to the region.
    assert!(unsafe { region.deref_mut() }.is_empty());
}

#[test]
fn parse_finds_ports_regions_and_an_inline_payload() {
    let bytes = RawMessage::new(true, 3)
        .port(7, 0)
        .port(8, 0)
        .region(0x1000 as *mut u8, 16)
        .inline_payload(b"hi")
        .bytes(MACH_PORT_NULL);

    let parsed = parse_message(&bytes).unwrap();

    assert_eq!(parsed.port_names, [7, 8]);
    assert_eq!(parsed.shared_memory_regions, [(0x1000 as *mut u8, 16)]);
    match parsed.payload {
        ReceivedPayload::Inline(range) => assert_eq!(&bytes[range], b"hi"),
        ReceivedPayload::OutOfLine(..) => panic!("expected an inline payload"),
    }
}

#[test]
fn parse_accepts_an_inline_payload_that_ends_the_message() {
    let bytes = RawMessage::new(false, 0)
        .inline_payload(b"abcd")
        .bytes(MACH_PORT_NULL);

    let parsed = parse_message(&bytes).unwrap();

    match parsed.payload {
        ReceivedPayload::Inline(range) => {
            assert_eq!(range.end, bytes.len());
            assert_eq!(&bytes[range], b"abcd");
        },
        ReceivedPayload::OutOfLine(..) => panic!("expected an inline payload"),
    }
}

#[test]
fn parse_takes_an_out_of_line_payload_from_the_last_region() {
    let bytes = RawMessage::new(true, 2)
        .region(0x1000 as *mut u8, 16)
        .region(0x2000 as *mut u8, 32)
        .out_of_line_payload()
        .bytes(MACH_PORT_NULL);

    let parsed = parse_message(&bytes).unwrap();

    assert_eq!(parsed.shared_memory_regions, [(0x1000 as *mut u8, 16)]);
    match parsed.payload {
        ReceivedPayload::OutOfLine(address, size) => {
            assert_eq!((address, size), (0x2000 as *mut u8, 32))
        },
        ReceivedPayload::Inline(_) => panic!("expected an out-of-line payload"),
    }
}

#[test]
fn parse_rejects_a_simple_message_that_claims_descriptors() {
    let bytes = RawMessage::new(false, 1)
        .region(0x1000 as *mut u8, 16)
        .out_of_line_payload()
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_more_descriptors_than_the_message_holds() {
    // The second descriptor would run past the end of the message.
    let bytes = RawMessage::new(true, u32::MAX)
        .region(0x1000 as *mut u8, 16)
        .out_of_line_payload()
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_a_port_after_a_region() {
    let bytes = RawMessage::new(true, 2)
        .region(0x1000 as *mut u8, 16)
        .port(7, 0)
        .inline_payload(b"hi")
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_descriptor_types_that_send_does_not_use() {
    let bytes = RawMessage::new(true, 1)
        .region_with(
            0x1000 as *mut u8,
            16,
            MACH_MSG_OOL_PORTS_DESCRIPTOR,
            MACH_MSG_VIRTUAL_COPY,
        )
        .inline_payload(b"hi")
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_an_inline_data_flag_that_is_not_a_bool() {
    let bytes = RawMessage::new(false, 0)
        .payload(2, 2, b"hi")
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_an_inline_payload_longer_than_the_message() {
    // A declared size of 4 would end the message exactly.
    for declared_size in [5, 4096, usize::MAX] {
        let bytes = RawMessage::new(false, 0)
            .payload(1, declared_size, b"abcd")
            .bytes(MACH_PORT_NULL);

        assert!(parse_message(&bytes).is_none());
    }
}

#[test]
fn parse_rejects_an_out_of_line_payload_without_a_region() {
    let bytes = RawMessage::new(false, 0)
        .out_of_line_payload()
        .bytes(MACH_PORT_NULL);

    assert!(parse_message(&bytes).is_none());
}

#[test]
fn parse_rejects_a_truncated_message() {
    let bytes = RawMessage::new(false, 0)
        .inline_payload(b"hi")
        .bytes(MACH_PORT_NULL);

    for length in [0, HEADER_SIZE, HEADER_SIZE + 4, bytes.len() - 4] {
        assert!(parse_message(&bytes[..length]).is_none());
    }
}
