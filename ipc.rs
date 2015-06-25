// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use platform::{self, OsIpcReceiver, OsIpcSender};

use serde::json;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cell::RefCell;
use std::marker::PhantomData;
use std::mem;

thread_local! {
    static OS_IPC_SENDERS_FOR_DESERIALIZATION: RefCell<Vec<OsIpcSender>> = RefCell::new(Vec::new())
}
thread_local! {
    static OS_IPC_SENDERS_FOR_SERIALIZATION: RefCell<Vec<OsIpcSender>> = RefCell::new(Vec::new())
}

pub fn channel<T>() -> Result<(IpcSender<T>, IpcReceiver<T>),()> where T: Deserialize + Serialize {
    let (os_sender, os_receiver) = match platform::channel() {
        Ok((os_sender, os_receiver)) => (os_sender, os_receiver),
        Err(_) => return Err(()),
    };
    let ipc_receiver = IpcReceiver {
        os_receiver: os_receiver,
        phantom: PhantomData,
    };
    let ipc_sender = IpcSender {
        os_sender: os_sender,
        phantom: PhantomData,
    };
    Ok((ipc_sender, ipc_receiver))
}

pub struct IpcReceiver<T> where T: Deserialize + Serialize {
    os_receiver: OsIpcReceiver,
    phantom: PhantomData<T>,
}

impl<T> IpcReceiver<T> where T: Deserialize + Serialize {
    pub fn recv(&self) -> Result<T,()> {
        let (data, mut os_ipc_senders) = match self.os_receiver.recv() {
            Ok((data, os_ipc_senders)) => (data, os_ipc_senders),
            Err(_) => return Err(()),
        };
        OS_IPC_SENDERS_FOR_DESERIALIZATION.with(|os_ipc_senders_for_deserialization| {
            mem::swap(&mut *os_ipc_senders_for_deserialization.borrow_mut(), &mut os_ipc_senders);
            let mut deserializer = match json::Deserializer::new(data.iter()
                                                                     .map(|byte| Ok(*byte))) {
                Ok(deserializer) => deserializer,
                Err(_) => return Err(()),
            };
            let result = match Deserialize::deserialize(&mut deserializer) {
                Ok(result) => result,
                Err(_) => return Err(()),
            };
            mem::swap(&mut *os_ipc_senders_for_deserialization.borrow_mut(), &mut os_ipc_senders);
            Ok(result)
        })
    }

    pub fn register_global_name(&self) -> Result<String,()> {
        self.os_receiver.register_global_name().map_err(|_| ())
    }

    pub fn unregister_global_name(name: String) -> Result<(),()> {
        OsIpcReceiver::unregister_global_name(name).map_err(|_| ())
    }
}

#[derive(Clone)]
pub struct IpcSender<T> where T: Serialize {
    os_sender: OsIpcSender,
    phantom: PhantomData<T>,
}

impl<T> IpcSender<T> where T: Serialize {
    pub fn from_global_name(name: String) -> Result<IpcSender<T>,()> {
        let os_sender = match OsIpcSender::from_global_name(name) {
            Ok(os_sender) => os_sender,
            Err(_) => return Err(()),
        };
        Ok(IpcSender {
            os_sender: os_sender,
            phantom: PhantomData,
        })
    }

    pub fn send(&self, data: T) -> Result<(),()> {
        let mut bytes = Vec::with_capacity(4096);
        OS_IPC_SENDERS_FOR_SERIALIZATION.with(|os_ipc_senders_for_serialization| {
            let old_os_ipc_senders =
                mem::replace(&mut *os_ipc_senders_for_serialization.borrow_mut(), Vec::new());
            let os_ipc_senders = {
                let mut serializer = json::Serializer::new(&mut bytes);
                data.serialize(&mut serializer).unwrap();
                mem::replace(&mut *os_ipc_senders_for_serialization.borrow_mut(),
                             old_os_ipc_senders)
            };
            self.os_sender.send(&bytes[..], os_ipc_senders).map_err(|_| ())
        })
    }
}

impl<T> Deserialize for IpcSender<T> where T: Serialize {
    fn deserialize<D>(deserializer: &mut D) -> Result<Self, D::Error> where D: Deserializer {
        let index: usize = try!(Deserialize::deserialize(deserializer));
        let os_sender =
            OS_IPC_SENDERS_FOR_DESERIALIZATION.with(|os_ipc_senders_for_deserialization| {
                // FIXME(pcwalton): This could panic. Return some sort of nice error.
                os_ipc_senders_for_deserialization.borrow_mut()[index].clone()
            });
        Ok(IpcSender {
            os_sender: os_sender,
            phantom: PhantomData,
        })
    }
}

impl<T> Serialize for IpcSender<T> where T: Serialize {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(),S::Error> where S: Serializer {
        let index = OS_IPC_SENDERS_FOR_SERIALIZATION.with(|os_ipc_senders_for_serialization| {
            let mut os_ipc_senders_for_serialization =
                os_ipc_senders_for_serialization.borrow_mut();
            let index = os_ipc_senders_for_serialization.len();
            os_ipc_senders_for_serialization.push(self.os_sender.clone());
            index
        });
        index.serialize(serializer)
    }
}

