// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use libc::c_int;

pub struct UnixReceiver {
    fd: c_int,
}

impl UnixReceiver {
    pub fn new() -> Result<UnixReceiver,c_int> {
        panic!()
    }
}

