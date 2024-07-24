// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{ffi, Error, ErrorInternal, Result};

/// Enum describing matching of rule towards packet flow direction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    #[default]
    Any = ffi::pfvar::PF_INOUT as u32 as u8,
    In = ffi::pfvar::PF_IN as u32 as u8,
    Out = ffi::pfvar::PF_OUT as u32 as u8,
}

impl From<Direction> for u8 {
    fn from(direction: Direction) -> Self {
        direction as u8
    }
}

impl TryFrom<u8> for Direction {
    type Error = crate::Error;

    fn try_from(direction: u8) -> Result<Self> {
        match direction {
            v if v == Direction::Any as u8 => Ok(Direction::Any),
            v if v == Direction::In as u8 => Ok(Direction::In),
            v if v == Direction::Out as u8 => Ok(Direction::Out),
            other => Err(Error::from(ErrorInternal::InvalidDirection(other))),
        }
    }
}
