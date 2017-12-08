// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use bincode;
use crossbeam_channel::{self, Receiver, Select, Sender};
use std::sync::{Arc, Mutex};
use std::collections::hash_map::HashMap;
use std::cell::{RefCell};
use std::io::{Error, ErrorKind};
use std::slice;
use std::fmt::{self, Debug, Formatter};
use std::cmp::{PartialEq};
use std::ops::{Deref, RangeFrom};
use std::usize;
use uuid::Uuid;

#[derive(Clone)]
struct ServerRecord {
    sender: OsIpcSender,
    conn_sender: Sender<bool>,
    conn_receiver: Receiver<bool>,
}

impl ServerRecord {
    fn new(sender: OsIpcSender) -> ServerRecord {
        let (tx, rx) = crossbeam_channel::unbounded::<bool>();
        ServerRecord {
            sender: sender,
            conn_sender: tx,
            conn_receiver: rx,
        }
    }

    fn accept(&self) {
        self.conn_receiver.recv().unwrap();
    }

    fn connect(&self) {
        self.conn_sender.send(true).unwrap();
    }
}

lazy_static! {
    static ref ONE_SHOT_SERVERS: Mutex<HashMap<String,ServerRecord>> = Mutex::new(HashMap::new());
}

struct ChannelMessage(Vec<u8>, Vec<OsIpcChannel>, Vec<OsIpcSharedMemory>);

pub fn channel() -> Result<(OsIpcSender, OsIpcReceiver), ChannelError> {
    let (base_sender, base_receiver) = crossbeam_channel::unbounded::<ChannelMessage>();
    Ok((OsIpcSender::new(base_sender), OsIpcReceiver::new(base_receiver)))
}

#[derive(Debug)]
pub struct OsIpcReceiver {
    receiver: RefCell<Option<Receiver<ChannelMessage>>>,
}

impl PartialEq for OsIpcReceiver {
    fn eq(&self, other: &OsIpcReceiver) -> bool {
        self.receiver.borrow().as_ref().map(|rx| rx as *const _) ==
            other.receiver.borrow().as_ref().map(|rx| rx as *const _)
    }
}

impl OsIpcReceiver {
    fn new(receiver: Receiver<ChannelMessage>) -> OsIpcReceiver {
        OsIpcReceiver {
            receiver: RefCell::new(Some(receiver)),
        }
    }

    pub fn consume(&self) -> OsIpcReceiver {
        let receiver = self.receiver.borrow_mut().take();
        OsIpcReceiver::new(receiver.unwrap())
    }

    pub fn recv(
        &self
    ) -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>), ChannelError> {
        let r = self.receiver.borrow();
        match r.as_ref().unwrap().recv() {
            Ok(ChannelMessage(d, c, s)) => {
                Ok((d, c.into_iter().map(OsOpaqueIpcChannel::new).collect(), s))
            }
            Err(_) => Err(ChannelError::ChannelClosedError),
        }
    }

    pub fn try_recv(
        &self
    ) -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>), ChannelError> {
        let r = self.receiver.borrow();
        match r.as_ref().unwrap().try_recv() {
            Ok(ChannelMessage(d, c, s)) => {
                Ok((d, c.into_iter().map(OsOpaqueIpcChannel::new).collect(), s))
            }
            Err(crossbeam_channel::TryRecvError::Disconnected) => {
                Err(ChannelError::ChannelClosedError)
            }
            Err(_) => Err(ChannelError::UnknownError),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OsIpcSender {
    sender: RefCell<Sender<ChannelMessage>>,
}

impl PartialEq for OsIpcSender {
    fn eq(&self, other: &OsIpcSender) -> bool {
        &*self.sender.borrow() as *const _ ==
            &*other.sender.borrow() as *const _
    }
}

impl OsIpcSender {
    fn new(sender: Sender<ChannelMessage>) -> OsIpcSender {
        OsIpcSender {
            sender: RefCell::new(sender),
        }
    }

    pub fn connect(name: String) -> Result<OsIpcSender, ChannelError> {
        let record = ONE_SHOT_SERVERS.lock().unwrap().get(&name).unwrap().clone();
        record.connect();
        Ok(record.sender)
    }

    pub fn get_max_fragment_size() -> usize {
        usize::MAX
    }

    pub fn send(
        &self,
        data: &[u8],
        ports: Vec<OsIpcChannel>,
        shared_memory_regions: Vec<OsIpcSharedMemory>,
    ) -> Result<(), ChannelError> {
        match self.sender
            .borrow()
            .send(ChannelMessage(data.to_vec(), ports, shared_memory_regions))
        {
            Err(_) => Err(ChannelError::BrokenPipeError),
            Ok(_) => Ok(()),
        }
    }
}

pub struct OsIpcReceiverSet {
    incrementor: RangeFrom<u64>,
    receiver_ids: Vec<u64>,
    receivers: Vec<OsIpcReceiver>,
}

impl OsIpcReceiverSet {
    pub fn new() -> Result<OsIpcReceiverSet, ChannelError> {
        Ok(OsIpcReceiverSet {
            incrementor: 0..,
            receiver_ids: vec![],
            receivers: vec![],
        })
    }

    pub fn add(&mut self, receiver: OsIpcReceiver) -> Result<u64, ChannelError> {
        let last_index = self.incrementor.next().unwrap();
        self.receiver_ids.push(last_index);
        self.receivers.push(receiver.consume());
        Ok(last_index)
    }

    pub fn select(&mut self) -> Result<Vec<OsIpcSelectionResult>, ChannelError> {
        if self.receivers.is_empty() {
            return Err(ChannelError::UnknownError);
        }

        let mut sel = Select::with_timeout(::std::time::Duration::from_secs(1));
        loop {
            for (index, rx) in self.receivers
                .iter_mut()
                .map(|r| r.receiver.get_mut().as_ref().unwrap())
                .enumerate()
            {
                if let Ok(msg) = sel.recv(rx) {
                    let r_id = self.receiver_ids[index];
                    let ChannelMessage(data, channels, shmems) = msg;
                    let channels = channels.into_iter().map(OsOpaqueIpcChannel::new).collect();
                    return Ok(vec![
                        OsIpcSelectionResult::DataReceived(r_id, data, channels, shmems),
                    ]);
                }
            }
            if sel.timed_out() { // TODO: this should be any_disconnected
                break;
            }
        }

        let (index, _) = self.receivers
            .iter_mut()
            .map(|r| r.receiver.get_mut().as_ref().unwrap())
            .enumerate()
            .find(|&(_, rx)| rx.is_disconnected())
            .unwrap();
        self.receivers.remove(index);
        let r_id = self.receiver_ids.remove(index);
        Ok(vec![OsIpcSelectionResult::ChannelClosed(r_id)])
    }
}

pub enum OsIpcSelectionResult {
    DataReceived(u64, Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),
    ChannelClosed(u64),
}

impl OsIpcSelectionResult {
    pub fn unwrap(self) -> (u64, Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>) {
        match self {
            OsIpcSelectionResult::DataReceived(id, data, channels, shared_memory_regions) => {
                (id, data, channels, shared_memory_regions)
            }
            OsIpcSelectionResult::ChannelClosed(id) => {
                panic!("OsIpcSelectionResult::unwrap(): receiver ID {} was closed!", id)
            }
        }
    }
}

pub struct OsIpcOneShotServer {
    receiver: OsIpcReceiver,
    name: String,
}

impl OsIpcOneShotServer {
    pub fn new() -> Result<(OsIpcOneShotServer, String), ChannelError> {
        let (sender, receiver) = try!(channel());

        let name = Uuid::new_v4().to_string();
        let record = ServerRecord::new(sender);
        ONE_SHOT_SERVERS.lock().unwrap().insert(name.clone(), record);
        Ok((OsIpcOneShotServer {
            receiver: receiver,
            name: name.clone(),
        },name.clone()))
    }

    pub fn accept(
        self,
    ) -> Result<
        (
            OsIpcReceiver,
            Vec<u8>,
            Vec<OsOpaqueIpcChannel>,
            Vec<OsIpcSharedMemory>,
        ),
        ChannelError,
    > {
        let record = ONE_SHOT_SERVERS
            .lock()
            .unwrap()
            .get(&self.name)
            .unwrap()
            .clone();
        record.accept();
        ONE_SHOT_SERVERS.lock().unwrap().remove(&self.name).unwrap();
        let (data, channels, shmems) = try!(self.receiver.recv());
        Ok((self.receiver, data, channels, shmems))
    }
}

#[derive(PartialEq, Debug)]
pub enum OsIpcChannel {
    Sender(OsIpcSender),
    Receiver(OsIpcReceiver),
}

#[derive(PartialEq, Debug)]
pub struct OsOpaqueIpcChannel {
    channel: RefCell<Option<OsIpcChannel>>,
}

impl OsOpaqueIpcChannel {
    fn new(channel: OsIpcChannel) -> OsOpaqueIpcChannel {
        OsOpaqueIpcChannel {
            channel: RefCell::new(Some(channel))
        }
    }

    pub fn to_receiver(&self) -> OsIpcReceiver {
        match self.channel.borrow_mut().take().unwrap() {
            OsIpcChannel::Sender(_) => panic!("Opaque channel is not a receiver!"),
            OsIpcChannel::Receiver(r) => r
        }
    }
    
    pub fn to_sender(&mut self) -> OsIpcSender {
        match self.channel.borrow_mut().take().unwrap() {
            OsIpcChannel::Sender(s) => s,
            OsIpcChannel::Receiver(_) => panic!("Opaque channel is not a sender!"),
        }
    }
}

pub struct OsIpcSharedMemory {
    ptr: *mut u8,
    length: usize,
    data: Arc<Vec<u8>>,
}

unsafe impl Send for OsIpcSharedMemory {}
unsafe impl Sync for OsIpcSharedMemory {}

impl Clone for OsIpcSharedMemory {
    fn clone(&self) -> OsIpcSharedMemory {
        OsIpcSharedMemory {
            ptr: self.ptr,
            length: self.length,
            data: self.data.clone(),
        }
    }
}

impl PartialEq for OsIpcSharedMemory {
    fn eq(&self, other: &OsIpcSharedMemory) -> bool {
        **self == **other
    }
}

impl Debug for OsIpcSharedMemory {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), fmt::Error> {
        (**self).fmt(formatter)
    }
}

impl Deref for OsIpcSharedMemory {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        if self.ptr.is_null() {
            panic!("attempted to access a consumed `OsIpcSharedMemory`")
        }
        unsafe {
            slice::from_raw_parts(self.ptr, self.length)
        }
    }
}

impl OsIpcSharedMemory {
    pub fn from_byte(byte: u8, length: usize) -> OsIpcSharedMemory {
        let mut v = Arc::new(vec![byte; length]);
        OsIpcSharedMemory {
            ptr: Arc::get_mut(&mut v).unwrap().as_mut_ptr(),
            length: length,
            data: v
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> OsIpcSharedMemory {
        let mut v = Arc::new(bytes.to_vec());
        OsIpcSharedMemory {
            ptr: Arc::get_mut(&mut v).unwrap().as_mut_ptr(),
            length: v.len(),
            data: v
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ChannelError {
    ChannelClosedError,
    BrokenPipeError,
    UnknownError,
}

impl ChannelError {
    #[allow(dead_code)]
    pub fn channel_is_closed(&self) -> bool {
        *self == ChannelError::ChannelClosedError
    }
}

impl From<ChannelError> for bincode::Error {
    fn from(crossbeam_error: ChannelError) -> Self {
        Error::from(crossbeam_error).into()
    }
}

impl From<ChannelError> for Error {
    fn from(crossbeam_error: ChannelError) -> Error {
        match crossbeam_error {
            ChannelError::ChannelClosedError => {
                Error::new(ErrorKind::ConnectionReset, "crossbeam-channel sender closed")
            }
            ChannelError::BrokenPipeError => {
                Error::new(ErrorKind::BrokenPipe, "crossbeam-channel receiver closed")
            }
            ChannelError::UnknownError => {
                Error::new(ErrorKind::Other, "Other crossbeam-channel error")
            }
        }
    }
}

