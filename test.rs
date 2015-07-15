// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use ipc::{self, IpcOneShotServer, IpcReceiver, IpcReceiverSet, IpcSender};
use router::ROUTER;

use libc;
use std::sync::mpsc::{self, Sender};
use std::thread;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Person {
    name: String,
    age: u32,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersonAndSender {
    person: Person,
    sender: IpcSender<Person>,
}

#[derive(Serialize, Deserialize)]
struct PersonAndReceiver {
    person: Person,
    receiver: IpcReceiver<Person>,
}

#[test]
fn simple() {
    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };
    let (tx, rx) = ipc::channel().unwrap();
    tx.send(person.clone()).unwrap();
    let received_person = rx.recv().unwrap();
    assert_eq!(person, received_person);
}

#[test]
fn embedded_senders() {
    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };
    let (sub_tx, sub_rx) = ipc::channel().unwrap();
    let person_and_sender = PersonAndSender {
        person: person.clone(),
        sender: sub_tx,
    };
    let (super_tx, super_rx) = ipc::channel().unwrap();
    super_tx.send(person_and_sender).unwrap();
    let received_person_and_sender = super_rx.recv().unwrap();
    assert_eq!(received_person_and_sender.person, person);
    received_person_and_sender.sender.send(person.clone()).unwrap();
    let received_person = sub_rx.recv().unwrap();
    assert_eq!(received_person, person);
}

#[test]
fn embedded_receivers() {
    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };
    let (sub_tx, sub_rx) = ipc::channel().unwrap();
    let person_and_receiver = PersonAndReceiver {
        person: person.clone(),
        receiver: sub_rx,
    };
    let (super_tx, super_rx) = ipc::channel().unwrap();
    super_tx.send(person_and_receiver).unwrap();
    let received_person_and_receiver = super_rx.recv().unwrap();
    assert_eq!(received_person_and_receiver.person, person);
    sub_tx.send(person.clone()).unwrap();
    let received_person = received_person_and_receiver.receiver.recv().unwrap();
    assert_eq!(received_person, person);
}

#[test]
fn select() {
    let (tx0, rx0) = ipc::channel().unwrap();
    let (tx1, rx1) = ipc::channel().unwrap();
    let mut rx_set = IpcReceiverSet::new().unwrap();
    let rx0_id = rx_set.add(rx0).unwrap();
    let rx1_id = rx_set.add(rx1).unwrap();

    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };
    tx0.send(person.clone()).unwrap();
    let (received_id, received_data) =
        rx_set.select().unwrap().into_iter().next().unwrap().unwrap();
    let received_person: Person = received_data.to().unwrap();
    assert_eq!(received_id, rx0_id);
    assert_eq!(received_person, person);

    tx1.send(person.clone()).unwrap();
    let (received_id, received_data) =
        rx_set.select().unwrap().into_iter().next().unwrap().unwrap();
    let received_person: Person = received_data.to().unwrap();
    assert_eq!(received_id, rx1_id);
    assert_eq!(received_person, person);

    tx0.send(person.clone()).unwrap();
    tx1.send(person.clone()).unwrap();
    let (mut received0, mut received1) = (false, false);
    while !received0 || !received1 {
        for result in rx_set.select().unwrap().into_iter() {
            let (received_id, received_data) = result.unwrap();
            let received_person: Person = received_data.to().unwrap();
            assert_eq!(received_person, person);
            assert!(received_id == rx0_id || received_id == rx1_id);
            if received_id == rx0_id {
                assert!(!received0);
                received0 = true;
            } else if received_id == rx1_id {
                assert!(!received1);
                received1 = true;
            }
        }
    }
}

#[test]
fn cross_process_embedded_senders() {
    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };
    let (server0, server0_name) = IpcOneShotServer::new().unwrap();
    let (server2, server2_name) = IpcOneShotServer::new().unwrap();
    unsafe {
        if libc::fork() == 0 {
            let (tx1, rx1): (IpcSender<Person>, IpcReceiver<Person>) = ipc::channel().unwrap();
            let tx0 = IpcSender::connect(server0_name).unwrap();
            tx0.send(tx1).unwrap();
            rx1.recv().unwrap();
            let tx2: IpcSender<Person> = IpcSender::connect(server2_name).unwrap();
            tx2.send(person.clone()).unwrap();
            libc::exit(0);
        }
    }
    let (_, tx1): (_, IpcSender<Person>) = server0.accept().unwrap();
    tx1.send(person.clone()).unwrap();
    let (_, received_person): (_, Person) = server2.accept().unwrap();
    assert_eq!(received_person, person);
}

#[test]
fn router_simple() {
    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };
    let (tx, rx) = ipc::channel().unwrap();
    tx.send(person.clone()).unwrap();

    let (callback_fired_sender, callback_fired_receiver) = mpsc::channel::<Person>();
    ROUTER.add_route(rx.to_opaque(), Box::new(move |person| {
        callback_fired_sender.send(person.to().unwrap()).unwrap()
    }));
    let received_person = callback_fired_receiver.recv().unwrap();
    assert_eq!(received_person, person);
}

#[test]
fn router_routing_to_mpsc_receiver() {
    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };
    let (tx, rx) = ipc::channel().unwrap();
    tx.send(person.clone()).unwrap();

    let mpsc_receiver = ROUTER.route_ipc_receiver_to_mpsc_receiver(rx);
    let received_person = mpsc_receiver.recv().unwrap();
    assert_eq!(received_person, person);
}

#[test]
fn router_multiplexing() {
    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };
    let (tx0, rx0) = ipc::channel().unwrap();
    tx0.send(person.clone()).unwrap();
    let (tx1, rx1) = ipc::channel().unwrap();
    tx1.send(person.clone()).unwrap();

    let mpsc_rx_0 = ROUTER.route_ipc_receiver_to_mpsc_receiver(rx0);
    let mpsc_rx_1 = ROUTER.route_ipc_receiver_to_mpsc_receiver(rx1);
    let received_person_0 = mpsc_rx_0.recv().unwrap();
    let received_person_1 = mpsc_rx_1.recv().unwrap();
    assert_eq!(received_person_0, person);
    assert_eq!(received_person_1, person);
}

#[test]
fn router_multithreaded_multiplexing() {
    let person = Person {
        name: "Patrick Walton".to_owned(),
        age: 29,
    };

    let person_for_thread = person.clone();
    let (tx0, rx0) = ipc::channel().unwrap();
    thread::spawn(move || tx0.send(person_for_thread).unwrap());
    let person_for_thread = person.clone();
    let (tx1, rx1) = ipc::channel().unwrap();
    thread::spawn(move || tx1.send(person_for_thread).unwrap());

    let mpsc_rx_0 = ROUTER.route_ipc_receiver_to_mpsc_receiver(rx0);
    let mpsc_rx_1 = ROUTER.route_ipc_receiver_to_mpsc_receiver(rx1);
    let received_person_0 = mpsc_rx_0.recv().unwrap();
    let received_person_1 = mpsc_rx_1.recv().unwrap();
    assert_eq!(received_person_0, person);
    assert_eq!(received_person_1, person);
}

#[test]
fn router_drops_callbacks_on_sender_shutdown() {
    struct Dropper {
        sender: Sender<i32>,
    }

    impl Drop for Dropper {
        fn drop(&mut self) {
            self.sender.send(42).unwrap()
        }
    }

    let (tx0, rx0) = ipc::channel::<()>().unwrap();
    let (drop_tx, drop_rx) = mpsc::channel();
    let dropper = Dropper {
        sender: drop_tx,
    };

    ROUTER.add_route(rx0.to_opaque(), Box::new(move |_| drop(&dropper)));
    drop(tx0);
    assert_eq!(drop_rx.recv(), Ok(42));
}

#[test]
fn router_drops_callbacks_on_cloned_sender_shutdown() {
    struct Dropper {
        sender: Sender<i32>,
    }

    impl Drop for Dropper {
        fn drop(&mut self) {
            self.sender.send(42).unwrap()
        }
    }

    let (tx0, rx0) = ipc::channel::<()>().unwrap();
    let (drop_tx, drop_rx) = mpsc::channel();
    let dropper = Dropper {
        sender: drop_tx,
    };

    ROUTER.add_route(rx0.to_opaque(), Box::new(move |_| drop(&dropper)));
    let txs = vec![tx0.clone(), tx0.clone(), tx0.clone()];
    drop(txs);
    drop(tx0);
    assert_eq!(drop_rx.recv(), Ok(42));
}

