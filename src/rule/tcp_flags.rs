// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::ffi;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpFlag {
    #[default]
    Any,
    Syn,
    Ack,
    Fin,
    Rst,
    Psh,
    Urg,
    Ece,
    Cwr,
}

impl From<TcpFlag> for u8 {
    fn from(tcp_flag: TcpFlag) -> Self {
        match tcp_flag {
            TcpFlag::Any => 0,
            TcpFlag::Fin => ffi::tcp::TH_FIN as u8,
            TcpFlag::Syn => ffi::tcp::TH_SYN as u8,
            TcpFlag::Rst => ffi::tcp::TH_RST as u8,
            TcpFlag::Psh => ffi::tcp::TH_PSH as u8,
            TcpFlag::Ack => ffi::tcp::TH_ACK as u8,
            TcpFlag::Urg => ffi::tcp::TH_URG as u8,
            TcpFlag::Ece => ffi::tcp::TH_ECE as u8,
            TcpFlag::Cwr => ffi::tcp::TH_CWR as u8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TcpFlagSet(Vec<TcpFlag>);

impl From<&TcpFlagSet> for u8 {
    fn from(set: &TcpFlagSet) -> Self {
        set.0.iter().fold(0, |acc, &x| (acc | u8::from(x)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TcpFlags {
    pub check: TcpFlagSet,
    pub mask: TcpFlagSet,
}

impl TcpFlags {
    pub fn new(check: &[TcpFlag], mask: &[TcpFlag]) -> Self {
        TcpFlags {
            check: TcpFlagSet(check.to_vec()),
            mask: TcpFlagSet(mask.to_vec()),
        }
    }
}

impl<CHECK: AsRef<[TcpFlag]>, MASK: AsRef<[TcpFlag]>> From<(CHECK, MASK)> for TcpFlags {
    fn from(pair: (CHECK, MASK)) -> Self {
        TcpFlags::new(pair.0.as_ref(), pair.1.as_ref())
    }
}
