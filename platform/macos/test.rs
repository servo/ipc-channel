// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[test]
fn simple() {
    let port0 = MachPort::new();
    let port1 = MachPort::new();
    port0.send(b"foo", Vec::new());
    assert_eq!(port1.recv(), (b"foo".iter().cloned().collect(), Vec::new()));
}

