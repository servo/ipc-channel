// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use ipc::{IpcReceiver, IpcSender};

use libc;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Person {
    name: String,
    age: u32,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersonAndChannel {
    person: Person,
    sender: IpcSender<Person>,
}

#[test]
fn simple() {
    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };
    let rx = IpcReceiver::new();
    let tx = rx.sender();
    tx.send(person.clone());
    let received_person = rx.recv();
    assert_eq!(person, received_person);
}

#[test]
fn embedded_channels() {
    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };
    let sub_rx = IpcReceiver::new();
    let sub_tx = sub_rx.sender();
    let person_and_channel = PersonAndChannel {
        person: person.clone(),
        sender: sub_tx,
    };
    let super_rx = IpcReceiver::new();
    let super_tx = super_rx.sender();
    super_tx.send(person_and_channel);
    let received_person_and_channel = super_rx.recv();
    assert_eq!(received_person_and_channel.person, person);
    received_person_and_channel.sender.send(person.clone());
    let received_person = sub_rx.recv();
    assert_eq!(received_person, person);
}

#[test]
fn cross_process_embedded_channels() {
    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };
    let rx0: IpcReceiver<IpcSender<Person>> = IpcReceiver::new();
    let rx0_name = rx0.register_global_name();
    let rx2: IpcReceiver<Person> = IpcReceiver::new();
    let rx2_name = rx2.register_global_name();
    unsafe {
        if libc::fork() == 0 {
            let rx1: IpcReceiver<Person> = IpcReceiver::new();
            let tx1: IpcSender<Person> = rx1.sender();
            let tx0 = IpcSender::from_global_name(rx0_name);
            tx0.send(tx1);
            rx1.recv();
            let tx2: IpcSender<Person> = IpcSender::from_global_name(rx2_name);
            tx2.send(person.clone());
            libc::exit(0);
        }
    }
    let tx1: IpcSender<Person> = rx0.recv();
    tx1.send(person.clone());
    let received_person = rx2.recv();
    assert_eq!(received_person, person);
}

