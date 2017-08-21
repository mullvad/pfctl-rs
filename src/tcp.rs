// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::os::raw::c_uint;

// exports from <netinet/tcp.h>
pub const TH_FIN: c_uint = 0x01;
pub const TH_SYN: c_uint = 0x02;
pub const TH_RST: c_uint = 0x04;
pub const TH_PSH: c_uint = 0x08;
pub const TH_ACK: c_uint = 0x10;
pub const TH_URG: c_uint = 0x20;
pub const TH_ECE: c_uint = 0x40;
pub const TH_CWR: c_uint = 0x80;
