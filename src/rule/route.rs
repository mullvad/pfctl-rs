// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{ffi, pooladdr::PoolAddr};

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub enum Route {
    #[default]
    NoRoute,
    RouteTo(PoolAddr),
    ReplyTo(PoolAddr),
    DupTo(PoolAddr),
}

impl Route {
    pub fn route_to<T: Into<PoolAddr>>(pool_addr: T) -> Self {
        Route::RouteTo(pool_addr.into())
    }

    pub fn reply_to<T: Into<PoolAddr>>(pool_addr: T) -> Self {
        Route::ReplyTo(pool_addr.into())
    }

    pub fn dup_to<T: Into<PoolAddr>>(pool_addr: T) -> Self {
        Route::DupTo(pool_addr.into())
    }

    pub fn get_pool_addr(&self) -> Option<&PoolAddr> {
        match *self {
            Route::NoRoute => None,
            Route::RouteTo(ref pool_addr) => Some(pool_addr),
            Route::ReplyTo(ref pool_addr) => Some(pool_addr),
            Route::DupTo(ref pool_addr) => Some(pool_addr),
        }
    }
}

impl<'a> From<&'a Route> for u8 {
    fn from(route: &'a Route) -> u8 {
        match *route {
            Route::NoRoute => ffi::pfvar::PF_NOPFROUTE as u8,
            Route::RouteTo(_) => ffi::pfvar::PF_ROUTETO as u8,
            Route::ReplyTo(_) => ffi::pfvar::PF_REPLYTO as u8,
            Route::DupTo(_) => ffi::pfvar::PF_DUPTO as u8,
        }
    }
}
