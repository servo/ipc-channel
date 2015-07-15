// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use platform::{self, OsIpcChannel, OsIpcReceiver, OsIpcReceiverSet, OsIpcSender};
use platform::{OsIpcOneShotServer, OsIpcSelectionResult, OsOpaqueIpcChannel};

use serde::json;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cell::RefCell;
use std::marker::PhantomData;
use std::mem;

thread_local! {
    static OS_IPC_CHANNELS_FOR_DESERIALIZATION: RefCell<Vec<OsOpaqueIpcChannel>> =
        RefCell::new(Vec::new())
}
thread_local! {
    static OS_IPC_CHANNELS_FOR_SERIALIZATION: RefCell<Vec<OsIpcChannel>> = RefCell::new(Vec::new())
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
        match self.os_receiver.recv() {
            Ok((data, os_ipc_channels)) => {
                OpaqueIpcMessage {
                    data: data,
                    os_ipc_channels: os_ipc_channels,
                }.to()
            }
            Err(_) => Err(()),
        }
    }

    pub fn to_opaque(self) -> OpaqueIpcReceiver {
        OpaqueIpcReceiver {
            os_receiver: self.os_receiver,
        }
    }
}

impl<T> Deserialize for IpcReceiver<T> where T: Deserialize + Serialize {
    fn deserialize<D>(deserializer: &mut D) -> Result<Self, D::Error> where D: Deserializer {
        let index: usize = try!(Deserialize::deserialize(deserializer));
        let os_receiver =
            OS_IPC_CHANNELS_FOR_DESERIALIZATION.with(|os_ipc_channels_for_deserialization| {
                // FIXME(pcwalton): This could panic. Return some sort of nice error.
                os_ipc_channels_for_deserialization.borrow_mut()[index].to_receiver()
            });
        Ok(IpcReceiver {
            os_receiver: os_receiver,
            phantom: PhantomData,
        })
    }
}

impl<T> Serialize for IpcReceiver<T> where T: Deserialize + Serialize {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(),S::Error> where S: Serializer {
        let index = OS_IPC_CHANNELS_FOR_SERIALIZATION.with(|os_ipc_channels_for_serialization| {
            let mut os_ipc_channels_for_serialization =
                os_ipc_channels_for_serialization.borrow_mut();
            let index = os_ipc_channels_for_serialization.len();
            os_ipc_channels_for_serialization.push(OsIpcChannel::Receiver(self.os_receiver
                                                                              .consume()));
            index
        });
        index.serialize(serializer)
    }
}

pub struct IpcSender<T> where T: Serialize {
    os_sender: OsIpcSender,
    phantom: PhantomData<T>,
}

impl<T> Clone for IpcSender<T> where T: Serialize {
    fn clone(&self) -> IpcSender<T> {
        IpcSender {
            os_sender: self.os_sender.clone(),
            phantom: PhantomData,
        }
    }
}

impl<T> IpcSender<T> where T: Serialize {
    pub fn connect(name: String) -> Result<IpcSender<T>,()> {
        let os_sender = match OsIpcSender::connect(name) {
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
        OS_IPC_CHANNELS_FOR_SERIALIZATION.with(|os_ipc_channels_for_serialization| {
            let old_os_ipc_channels =
                mem::replace(&mut *os_ipc_channels_for_serialization.borrow_mut(), Vec::new());
            let os_ipc_channels = {
                let mut serializer = json::Serializer::new(&mut bytes);
                data.serialize(&mut serializer).unwrap();
                mem::replace(&mut *os_ipc_channels_for_serialization.borrow_mut(),
                             old_os_ipc_channels)
            };
            self.os_sender.send(&bytes[..], os_ipc_channels).map_err(|_| ())
        })
    }
}

impl<T> Deserialize for IpcSender<T> where T: Serialize {
    fn deserialize<D>(deserializer: &mut D) -> Result<Self, D::Error> where D: Deserializer {
        let index: usize = try!(Deserialize::deserialize(deserializer));
        let os_sender =
            OS_IPC_CHANNELS_FOR_DESERIALIZATION.with(|os_ipc_channels_for_deserialization| {
                // FIXME(pcwalton): This could panic. Return some sort of nice error.
                os_ipc_channels_for_deserialization.borrow_mut()[index].to_sender()
            });
        Ok(IpcSender {
            os_sender: os_sender,
            phantom: PhantomData,
        })
    }
}

impl<T> Serialize for IpcSender<T> where T: Serialize {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(),S::Error> where S: Serializer {
        let index = OS_IPC_CHANNELS_FOR_SERIALIZATION.with(|os_ipc_channels_for_serialization| {
            let mut os_ipc_channels_for_serialization =
                os_ipc_channels_for_serialization.borrow_mut();
            let index = os_ipc_channels_for_serialization.len();
            os_ipc_channels_for_serialization.push(OsIpcChannel::Sender(self.os_sender.clone()));
            index
        });
        index.serialize(serializer)
    }
}

pub struct IpcReceiverSet {
    os_receiver_set: OsIpcReceiverSet,
}

impl IpcReceiverSet {
    pub fn new() -> Result<IpcReceiverSet,()> {
        match OsIpcReceiverSet::new() {
            Ok(os_receiver_set) => {
                Ok(IpcReceiverSet {
                    os_receiver_set: os_receiver_set,
                })
            }
            Err(_) => Err(()),
        }
    }

    pub fn add<T>(&mut self, receiver: IpcReceiver<T>) -> Result<i64,()>
                  where T: Deserialize + Serialize {
        self.os_receiver_set.add(receiver.os_receiver).map_err(|_| ())
    }

    pub fn add_opaque(&mut self, receiver: OpaqueIpcReceiver) -> Result<i64,()> {
        self.os_receiver_set.add(receiver.os_receiver).map_err(|_| ())
    }

    pub fn select(&mut self) -> Result<Vec<IpcSelectionResult>,()> {
        match self.os_receiver_set.select() {
            Ok(results) => {
                Ok(results.into_iter().map(|result| {
                    match result {
                        OsIpcSelectionResult::DataReceived(os_receiver_id,
                                                           data,
                                                           os_ipc_channels) => {
                            IpcSelectionResult::MessageReceived(os_receiver_id, OpaqueIpcMessage {
                                data: data,
                                os_ipc_channels: os_ipc_channels,
                            })
                        }
                        OsIpcSelectionResult::ChannelClosed(os_receiver_id) => {
                            IpcSelectionResult::ChannelClosed(os_receiver_id)
                        }
                    }
                }).collect())
            }
            Err(err) => {
                println!("Aieeee! {:?}", err);
                Err(())
            }
        }
    }
}

pub enum IpcSelectionResult {
    MessageReceived(i64, OpaqueIpcMessage),
    ChannelClosed(i64),
}

impl IpcSelectionResult {
    pub fn unwrap(self) -> (i64, OpaqueIpcMessage) {
        match self {
            IpcSelectionResult::MessageReceived(id, message) => (id, message),
            IpcSelectionResult::ChannelClosed(id) => {
                panic!("IpcSelectionResult::unwrap(): channel {} closed", id)
            }
        }
    }
}

pub struct OpaqueIpcMessage {
    data: Vec<u8>,
    os_ipc_channels: Vec<OsOpaqueIpcChannel>,
}

impl OpaqueIpcMessage {
    pub fn to<T>(mut self) -> Result<T,()> where T: Deserialize + Serialize {
        OS_IPC_CHANNELS_FOR_DESERIALIZATION.with(|os_ipc_channels_for_deserialization| {
            mem::swap(&mut *os_ipc_channels_for_deserialization.borrow_mut(),
                      &mut self.os_ipc_channels);
            let mut deserializer = match json::Deserializer::new(self.data
                                                                     .iter()
                                                                     .map(|byte| Ok(*byte))) {
                Ok(deserializer) => deserializer,
                Err(_) => return Err(()),
            };
            let result = match Deserialize::deserialize(&mut deserializer) {
                Ok(result) => result,
                Err(_) => return Err(()),
            };
            mem::swap(&mut *os_ipc_channels_for_deserialization.borrow_mut(),
                      &mut self.os_ipc_channels);
            Ok(result)
        })
    }
}

pub struct OpaqueIpcReceiver {
    os_receiver: OsIpcReceiver,
}

pub struct IpcOneShotServer<T> {
    os_server: OsIpcOneShotServer,
    phantom: PhantomData<T>,
}

impl<T> IpcOneShotServer<T> where T: Deserialize + Serialize {
    pub fn new() -> Result<(IpcOneShotServer<T>, String),()> {
        let (os_server, name) = match OsIpcOneShotServer::new() {
            Ok(result) => result,
            Err(_) => return Err(()),
        };
        Ok((IpcOneShotServer {
            os_server: os_server,
            phantom: PhantomData,
        }, name))
    }

    pub fn accept(self) -> Result<(IpcReceiver<T>,T),()> {
        let (os_receiver, data, os_channels) = match self.os_server.accept() {
            Ok(result) => result,
            Err(_) => return Err(()),
        };
        let value = try!(OpaqueIpcMessage {
            data: data,
            os_ipc_channels: os_channels,
        }.to());
        Ok((IpcReceiver {
            os_receiver: os_receiver,
            phantom: PhantomData,
        }, value))
    }
}

