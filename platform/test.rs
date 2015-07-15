// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use libc;
use platform::{self, OsIpcChannel, OsIpcReceiverSet, OsIpcSender, OsIpcOneShotServer};
use std::iter;
use std::thread;

#[test]
fn simple() {
    let (tx, rx) = platform::channel().unwrap();
    let data: &[u8] = b"1234567";
    tx.send(data, Vec::new()).unwrap();
    let (mut received_data, received_channels) = rx.recv().unwrap();
    received_data.truncate(7);
    assert_eq!((&received_data[..], received_channels), (data, Vec::new()));
}

#[test]
fn sender_transfer() {
    let (super_tx, super_rx) = platform::channel().unwrap();
    let (sub_tx, sub_rx) = platform::channel().unwrap();
    let data: &[u8] = b"foo";
    super_tx.send(data, vec![OsIpcChannel::Sender(sub_tx)]).unwrap();
    let (_, mut received_channels) = super_rx.recv().unwrap();
    assert_eq!(received_channels.len(), 1);
    let sub_tx = received_channels.pop().unwrap().to_sender();
    sub_tx.send(data, vec![]).unwrap();
    let (mut received_data, received_channels) = sub_rx.recv().unwrap();
    received_data.truncate(3);
    assert_eq!((&received_data[..], received_channels), (data, Vec::new()));
}

#[test]
fn receiver_transfer() {
    let (super_tx, super_rx) = platform::channel().unwrap();
    let (sub_tx, sub_rx) = platform::channel().unwrap();
    let data: &[u8] = b"foo";
    super_tx.send(data, vec![OsIpcChannel::Receiver(sub_rx)]).unwrap();
    let (_, mut received_channels) = super_rx.recv().unwrap();
    assert_eq!(received_channels.len(), 1);
    let sub_rx = received_channels.pop().unwrap().to_receiver();
    sub_tx.send(data, vec![]).unwrap();
    let (mut received_data, received_channels) = sub_rx.recv().unwrap();
    received_data.truncate(3);
    assert_eq!((&received_data[..], received_channels), (data, Vec::new()));
}

#[test]
fn multisender_transfer() {
    let (super_tx, super_rx) = platform::channel().unwrap();
    let (sub0_tx, sub0_rx) = platform::channel().unwrap();
    let (sub1_tx, sub1_rx) = platform::channel().unwrap();
    let data: &[u8] = b"asdfasdf";
    super_tx.send(data,
                  vec![OsIpcChannel::Sender(sub0_tx), OsIpcChannel::Sender(sub1_tx)]).unwrap();
    let (_, mut received_channels) = super_rx.recv().unwrap();
    assert_eq!(received_channels.len(), 2);

    let sub0_tx = received_channels.remove(0).to_sender();
    sub0_tx.send(data, vec![]).unwrap();
    let (mut received_data, received_subchannels) = sub0_rx.recv().unwrap();
    received_data.truncate(8);
    assert_eq!((&received_data[..], received_subchannels), (data, Vec::new()));

    let sub1_tx = received_channels.remove(0).to_sender();
    sub1_tx.send(data, vec![]).unwrap();
    let (mut received_data, received_subchannels) = sub1_rx.recv().unwrap();
    received_data.truncate(8);
    assert_eq!((&received_data[..], received_subchannels), (data, Vec::new()));
}

#[test]
fn big_data() {
    let data: Vec<u8> = iter::repeat(0xba).take(65536).collect();
    let data: &[u8] = &data[..];
    let (tx, rx) = platform::channel().unwrap();
    tx.send(data, Vec::new()).unwrap();
    let (mut received_data, received_channels) = rx.recv().unwrap();
    received_data.truncate(65536);
    assert_eq!((&received_data[..], received_channels), (&data[..], Vec::new()));
}

#[test]
fn big_data_with_sender_transfer() {
    let data: Vec<u8> = iter::repeat(0xba).take(65536).collect();
    let data: &[u8] = &data[..];
    let (super_tx, super_rx) = platform::channel().unwrap();
    let (sub_tx, sub_rx) = platform::channel().unwrap();
    super_tx.send(data, vec![OsIpcChannel::Sender(sub_tx)]).unwrap();
    let (_, mut received_channels) = super_rx.recv().unwrap();
    assert_eq!(received_channels.len(), 1);
    let sub_tx = received_channels.pop().unwrap().to_sender();
    sub_tx.send(data, vec![]).unwrap();
    let (mut received_data, received_channels) = sub_rx.recv().unwrap();
    received_data.truncate(65536);
    assert_eq!((&received_data[..], received_channels), (data, Vec::new()));
}

#[test]
fn receiver_set() {
    let (tx0, rx0) = platform::channel().unwrap();
    let (tx1, rx1) = platform::channel().unwrap();
    let mut rx_set = OsIpcReceiverSet::new().unwrap();
    let rx0_id = rx_set.add(rx0).unwrap();
    let rx1_id = rx_set.add(rx1).unwrap();

    let data: &[u8] = b"1234567";
    tx0.send(data, Vec::new()).unwrap();
    let (received_id, mut received_data, _) =
        rx_set.select().unwrap().into_iter().next().unwrap().unwrap();
    received_data.truncate(7);
    assert_eq!(received_id, rx0_id);
    assert_eq!(received_data, data);

    tx1.send(data, Vec::new()).unwrap();
    let (received_id, mut received_data, _) =
        rx_set.select().unwrap().into_iter().next().unwrap().unwrap();
    received_data.truncate(7);
    assert_eq!(received_id, rx1_id);
    assert_eq!(received_data, data);

    tx0.send(data, Vec::new()).unwrap();
    tx1.send(data, Vec::new()).unwrap();
    let (received_id_0, mut received_data, _) =
        rx_set.select().unwrap().into_iter().next().unwrap().unwrap();
    received_data.truncate(7);
    assert_eq!(received_data, data);
    assert!(received_id_0 == rx0_id || received_id_0 == rx1_id);
    let (received_id_1, mut received_data, _) =
        rx_set.select().unwrap().into_iter().next().unwrap().unwrap();
    received_data.truncate(7);
    assert_eq!(received_data, data);
    assert!(received_id_1 == rx0_id || received_id_1 == rx1_id);
    assert!(received_id_0 != received_id_1);
}

#[test]
fn server() {
    let (server, name) = OsIpcOneShotServer::new().unwrap();
    let data: &[u8] = b"1234567";

    thread::spawn(move || {
        let tx = OsIpcSender::connect(name).unwrap();
        tx.send(data, Vec::new()).unwrap();
    });

    let (_, mut received_data, received_channels) = server.accept().unwrap();
    received_data.truncate(7);
    assert_eq!((&received_data[..], received_channels), (data, Vec::new()));
}

#[test]
fn cross_process() {
    let (server, name) = OsIpcOneShotServer::new().unwrap();
    let data: &[u8] = b"1234567";

    unsafe {
        if libc::fork() == 0 {
            let tx = OsIpcSender::connect(name).unwrap();
            tx.send(data, Vec::new()).unwrap();
            libc::exit(0);
        }
    }

    let (_, mut received_data, received_channels) = server.accept().unwrap();
    received_data.truncate(7);
    assert_eq!((&received_data[..], received_channels), (data, Vec::new()));
}

#[test]
fn cross_process_sender_transfer() {
    let (server, name) = OsIpcOneShotServer::new().unwrap();

    unsafe {
        if libc::fork() == 0 {
            let super_tx = OsIpcSender::connect(name).unwrap();
            let (sub_tx, sub_rx) = platform::channel().unwrap();
            let data: &[u8] = b"foo";
            super_tx.send(data, vec![OsIpcChannel::Sender(sub_tx)]).unwrap();
            sub_rx.recv().unwrap();
            let data: &[u8] = b"bar";
            super_tx.send(data, Vec::new()).unwrap();
            libc::exit(0);
        }
    }

    let (super_rx, _, mut received_channels) = server.accept().unwrap();
    assert_eq!(received_channels.len(), 1);
    let sub_tx = received_channels.pop().unwrap().to_sender();
    let data: &[u8] = b"baz";
    sub_tx.send(data, Vec::new()).unwrap();

    let data: &[u8] = b"bar";
    let (mut received_data, received_channels) = super_rx.recv().unwrap();
    received_data.truncate(3);
    assert_eq!((&received_data[..], received_channels), (data, Vec::new()));
}

#[test]
fn no_senders_notification() {
    let (sender, receiver) = platform::channel().unwrap();
    drop(sender);
    let result = receiver.recv();
    assert!(result.is_err());
    assert!(result.unwrap_err().channel_is_closed());
}

