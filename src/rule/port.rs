// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use conversion::TryCopyTo;
use ffi;
use {ErrorKind, Result};

// Port range representation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Port {
    Any,
    One(u16, PortUnaryModifier),
    Range(u16, u16, PortRangeModifier),
}

impl Default for Port {
    fn default() -> Self {
        Port::Any
    }
}

impl From<u16> for Port {
    fn from(port: u16) -> Self {
        Port::One(port, PortUnaryModifier::Equal)
    }
}

impl TryCopyTo<ffi::pfvar::pf_port_range> for Port {
    fn try_copy_to(&self, pf_port_range: &mut ffi::pfvar::pf_port_range) -> Result<()> {
        match *self {
            Port::Any => {
                pf_port_range.op = ffi::pfvar::PF_OP_NONE as u8;
                pf_port_range.port[0] = 0;
                pf_port_range.port[1] = 0;
            }
            Port::One(port, modifier) => {
                pf_port_range.op = modifier.into();
                // convert port range to network byte order
                pf_port_range.port[0] = port.to_be();
                pf_port_range.port[1] = 0;
            }
            Port::Range(start_port, end_port, modifier) => {
                ensure!(
                    start_port <= end_port,
                    ErrorKind::InvalidArgument("Lower port is greater than upper port.")
                );
                pf_port_range.op = modifier.into();
                // convert port range to network byte order
                pf_port_range.port[0] = start_port.to_be();
                pf_port_range.port[1] = end_port.to_be();
            }
        }
        Ok(())
    }
}

impl TryCopyTo<ffi::pfvar::pf_pool> for Port {
    fn try_copy_to(&self, pf_pool: &mut ffi::pfvar::pf_pool) -> Result<()> {
        match *self {
            Port::Any => {
                pf_pool.port_op = ffi::pfvar::PF_OP_NONE as u8;
                pf_pool.proxy_port[0] = 0;
                pf_pool.proxy_port[1] = 0;
            }
            Port::One(port, modifier) => {
                pf_pool.port_op = modifier.into();
                pf_pool.proxy_port[0] = port;
                pf_pool.proxy_port[1] = 0;
            }
            Port::Range(start_port, end_port, modifier) => {
                ensure!(
                    start_port <= end_port,
                    ErrorKind::InvalidArgument("Lower port is greater than upper port.")
                );
                pf_pool.port_op = modifier.into();
                pf_pool.proxy_port[0] = start_port;
                pf_pool.proxy_port[1] = end_port;
            }
        }
        Ok(())
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortUnaryModifier {
    Equal,
    NotEqual,
    Greater,
    Less,
    GreaterOrEqual,
    LessOrEqual,
}

impl From<PortUnaryModifier> for u8 {
    fn from(modifier: PortUnaryModifier) -> Self {
        match modifier {
            PortUnaryModifier::Equal => ffi::pfvar::PF_OP_EQ as u8,
            PortUnaryModifier::NotEqual => ffi::pfvar::PF_OP_NE as u8,
            PortUnaryModifier::Greater => ffi::pfvar::PF_OP_GT as u8,
            PortUnaryModifier::Less => ffi::pfvar::PF_OP_LT as u8,
            PortUnaryModifier::GreaterOrEqual => ffi::pfvar::PF_OP_GE as u8,
            PortUnaryModifier::LessOrEqual => ffi::pfvar::PF_OP_LE as u8,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortRangeModifier {
    Exclusive,
    Inclusive,
    Except,
}

impl From<PortRangeModifier> for u8 {
    fn from(modifier: PortRangeModifier) -> Self {
        match modifier {
            PortRangeModifier::Exclusive => ffi::pfvar::PF_OP_IRG as u8,
            PortRangeModifier::Inclusive => ffi::pfvar::PF_OP_RRG as u8,
            PortRangeModifier::Except => ffi::pfvar::PF_OP_XRG as u8,
        }
    }
}
