// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::sync::mpsc;
use std::sync::{Arc, Mutex, Condvar};
use std::collections::hash_map::HashMap;
use std::cell::{RefCell};
use std::io::{Error, ErrorKind};
use std::slice;
use std::fmt::{self, Debug, Formatter};
use std::cmp::{PartialEq};
use std::ops::Deref;
use std::mem;

use uuid::Uuid;

struct ServerRecord {
    sender: MpscSender,
    conn_sender: mpsc::Sender<bool>,
    conn_receiver: Mutex<mpsc::Receiver<bool>>,
}

impl ServerRecord {
    fn new(sender: MpscSender) -> ServerRecord {
        let (tx, rx) = mpsc::channel::<bool>();
        ServerRecord {
            sender: sender,
            conn_sender: tx,
            conn_receiver: Mutex::new(rx),
        }
    }

    fn accept(&self) {
        self.conn_receiver.lock().unwrap().recv().unwrap();
    }

    fn connect(&self) {
        self.conn_sender.send(true).unwrap();
    }
}

lazy_static! {
    static ref ONE_SHOT_SERVERS: Mutex<HashMap<String,ServerRecord>> = Mutex::new(HashMap::new());
}

struct MpscChannelMessage(Vec<u8>, Vec<MpscChannel>, Vec<MpscSharedMemory>);

pub fn channel() -> Result<(MpscSender, MpscReceiver),MpscError> {
    let (base_sender, base_receiver) = mpsc::channel::<MpscChannelMessage>();
    Ok((MpscSender::new(base_sender), MpscReceiver::new(base_receiver)))
}

pub struct MpscReceiver {
    receiver: RefCell<Option<mpsc::Receiver<MpscChannelMessage>>>,
}

// Can't derive, as mpsc::Receiver doesn't implement Debug.
impl fmt::Debug for MpscReceiver {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Not sure there is anything useful we could print here.
        write!(f, "MpscReceiver {{ .. }}")
    }
}

impl MpscReceiver {
    fn new(receiver: mpsc::Receiver<MpscChannelMessage>) -> MpscReceiver {
        MpscReceiver {
            receiver: RefCell::new(Some(receiver)),
        }
    }

    pub fn consume(&self) -> MpscReceiver {
        let receiver = self.receiver.borrow_mut().take();
        MpscReceiver::new(receiver.unwrap())
    }

    pub fn recv(&self) -> Result<(Vec<u8>, Vec<OpaqueMpscChannel>, Vec<MpscSharedMemory>),MpscError> {
        let r = self.receiver.borrow();
        match r.as_ref().unwrap().recv() {
            Ok(MpscChannelMessage(d,c,s)) => Ok((d,
                                                 c.into_iter().map(OpaqueMpscChannel::new).collect(),
                                                 s)),
            Err(_) => Err(MpscError::ChannelClosedError),
        }
    }

    pub fn try_recv(&self) -> Result<(Vec<u8>, Vec<OpaqueMpscChannel>, Vec<MpscSharedMemory>),MpscError> {
        let r = self.receiver.borrow();
        match r.as_ref().unwrap().try_recv() {
            Ok(MpscChannelMessage(d,c,s)) => Ok((d,
                                                 c.into_iter().map(OpaqueMpscChannel::new).collect(),
                                                 s)),
            Err(_) => Err(MpscError::ChannelClosedError),
        }
    }
}

unsafe impl Send for MpscReceiver { }
unsafe impl Sync for MpscReceiver { }

#[derive(Clone)]
pub struct MpscSender {
    sender: RefCell<mpsc::Sender<MpscChannelMessage>>,
}

// Can't derive, as mpsc::Sender doesn't implement Debug.
impl fmt::Debug for MpscSender {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Not sure there is anything useful we could print here.
        write!(f, "MpscSender {{ .. }}")
    }
}

unsafe impl Send for MpscSender { }
unsafe impl Sync for MpscSender { }

impl MpscSender {
    fn new(sender: mpsc::Sender<MpscChannelMessage>) -> MpscSender {
        MpscSender {
            sender: RefCell::new(sender),
        }
    }

    pub fn connect(name: String) -> Result<MpscSender,MpscError> {
        let record = ONE_SHOT_SERVERS.lock().unwrap().remove(&name).unwrap();
        record.connect();
        Ok(record.sender)
    }

    pub fn send(&self,
                data: &[u8],
                ports: Vec<MpscChannel>,
                shared_memory_regions: Vec<MpscSharedMemory>)
                -> Result<(),MpscError>
    {
        match self.sender.borrow().send(MpscChannelMessage(data.to_vec(), ports, shared_memory_regions)) {
            Err(_) => Err(MpscError::ChannelClosedError),
            Ok(_) => Ok(()),
        }
    }
}

pub struct MpscReceiverSet {
    last_index: usize,
    receiver_ids: Vec<usize>,
    receivers: Vec<MpscReceiver>,
}

impl MpscReceiverSet {
    pub fn new() -> Result<MpscReceiverSet,MpscError> {
        Ok(MpscReceiverSet {
            last_index: 0,
            receiver_ids: vec![],
            receivers: vec![],
        })
    }

    pub fn add(&mut self, receiver: MpscReceiver) -> Result<i64,MpscError> {
        self.last_index += 1;
        self.receiver_ids.push(self.last_index);
        self.receivers.push(receiver.consume());
        Ok(self.last_index as i64)
    }

    pub fn select(&mut self) -> Result<Vec<MpscSelectionResult>,MpscError> {
        let mut receivers: Vec<Option<mpsc::Receiver<MpscChannelMessage>>> = Vec::with_capacity(self.receivers.len());
        let mut r_id: i64 = -1;
        let mut r_index: usize = 0;

        {
            let select = mpsc::Select::new();
            // we *must* allocate exact capacity for this, because the Handles *can't move*
            let mut handles: Vec<mpsc::Handle<MpscChannelMessage>> = Vec::with_capacity(self.receivers.len());

            for r in &self.receivers {
                let inner_r = mem::replace(&mut *r.receiver.borrow_mut(), None);
                receivers.push(inner_r);
            }
            
            for r in &receivers {
                unsafe {
                    handles.push(select.handle(r.as_ref().unwrap()));
                    handles.last_mut().unwrap().add();
                }
            }

            let id = select.wait();

            for (index,h) in handles.iter().enumerate() {
                if h.id() == id {
                    r_index = index;
                    r_id = self.receiver_ids[index] as i64;
                    break;
                }
            }
        }

        // put the receivers back
        for (index,r) in self.receivers.iter().enumerate() {
            mem::replace(&mut *r.receiver.borrow_mut(), mem::replace(&mut receivers[index], None));
        }

        if r_id == -1 {
            return Err(MpscError::UnknownError);
        }

        let receivers = &mut self.receivers;
        match receivers[r_index].recv() {
            Ok((data, channels, shmems)) =>
                Ok(vec![MpscSelectionResult::DataReceived(r_id, data, channels, shmems)]),
            Err(MpscError::ChannelClosedError) => {
                receivers.remove(r_index);
                self.receiver_ids.remove(r_index);
                Ok(vec![MpscSelectionResult::ChannelClosed(r_id)])
            },
            Err(err) => Err(err),
        }
    }
}

pub enum MpscSelectionResult {
    DataReceived(i64, Vec<u8>, Vec<OpaqueMpscChannel>, Vec<MpscSharedMemory>),
    ChannelClosed(i64),
}

pub struct MpscOneShotServer {
    receiver: RefCell<Option<MpscReceiver>>,
    name: String,
}

impl MpscOneShotServer {
    pub fn new() -> Result<(MpscOneShotServer, String),MpscError> {
        let (sender, receiver) = match channel() {
            Ok((s,r)) => (s,r),
            Err(err) => return Err(err),
        };

        let name = Uuid::new_v4().to_string();
        let record = ServerRecord::new(sender);
        ONE_SHOT_SERVERS.lock().unwrap().insert(name.clone(), record);
        Ok((MpscOneShotServer {
            receiver: RefCell::new(Some(receiver)),
            name: name.clone(),
        },name.clone()))
    }

    pub fn accept(&self) -> Result<(MpscReceiver,
                                    Vec<u8>,
                                    Vec<OpaqueMpscChannel>,
                                    Vec<MpscSharedMemory>),MpscError>
    {
        ONE_SHOT_SERVERS.lock().unwrap().get(&self.name).unwrap().accept();
        let receiver = self.receiver.borrow_mut().take().unwrap();
        let (data, channels, shmems) = receiver.recv().unwrap();
        Ok((receiver, data, channels, shmems))
    }
}

pub enum MpscChannel {
    Sender(MpscSender),
    Receiver(MpscReceiver),
}

pub struct OpaqueMpscChannel {
    channel: RefCell<Option<MpscChannel>>,
}

impl OpaqueMpscChannel {
    fn new(channel: MpscChannel) -> OpaqueMpscChannel {
        OpaqueMpscChannel {
            channel: RefCell::new(Some(channel))
        }
    }

    pub fn to_receiver(&self) -> MpscReceiver {
        match self.channel.borrow_mut().take().unwrap() {
            MpscChannel::Sender(_) => panic!("Opaque channel is not a receiver!"),
            MpscChannel::Receiver(r) => r
        }
    }
    
    pub fn to_sender(&self) -> MpscSender {
        match self.channel.borrow_mut().take().unwrap() {
            MpscChannel::Sender(s) => s,
            MpscChannel::Receiver(_) => panic!("Opaque channel is not a sender!"),
        }
    }
}

pub struct MpscSharedMemory {
    ptr: *mut u8,
    length: usize,
    data: Arc<Vec<u8>>,
}

unsafe impl Send for MpscSharedMemory {}
unsafe impl Sync for MpscSharedMemory {}

impl Clone for MpscSharedMemory {
    fn clone(&self) -> MpscSharedMemory {
        MpscSharedMemory {
            ptr: self.ptr,
            length: self.length,
            data: self.data.clone(),
        }
    }
}

impl PartialEq for MpscSharedMemory {
    fn eq(&self, other: &MpscSharedMemory) -> bool {
        **self == **other
    }
}

impl Debug for MpscSharedMemory {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), fmt::Error> {
        (**self).fmt(formatter)
    }
}

impl Deref for MpscSharedMemory {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        if self.ptr.is_null() {
            panic!("attempted to access a consumed `MpscSharedMemory`")
        }
        unsafe {
            slice::from_raw_parts(self.ptr, self.length)
        }
    }
}

impl MpscSharedMemory {
    pub fn from_byte(byte: u8, length: usize) -> MpscSharedMemory {
        let mut v = Arc::new(vec![byte; length]);
        MpscSharedMemory {
            ptr: Arc::get_mut(&mut v).unwrap().as_mut_ptr(),
            length: length,
            data: v
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> MpscSharedMemory {
        let mut v = Arc::new(bytes.to_vec());
        MpscSharedMemory {
            ptr: Arc::get_mut(&mut v).unwrap().as_mut_ptr(),
            length: v.len(),
            data: v
        }
    }
}

#[derive(Debug)]
pub enum MpscError {
    ChannelClosedError,
    UnknownError,
}

impl From<MpscError> for Error {
    fn from(mpsc_error: MpscError) -> Error {
        match mpsc_error {
            MpscError::ChannelClosedError => {
                Error::new(ErrorKind::BrokenPipe, "MPSC channel closed")
            }
            MpscError::UnknownError => Error::new(ErrorKind::Other, "Other MPSC channel error"),
        }
    }
}

