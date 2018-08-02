#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod bccapi {
	include!(concat!("../bindings/bccapi.rs"));
}

pub mod core;
pub mod symbol;
pub mod perf;
pub mod table;
mod types;
mod cpuonline;

#[macro_use]
extern crate failure;
extern crate libc;
// extern crate bcc_sys;
extern crate byteorder;
#[cfg(test)] #[macro_use]
extern crate lazy_static;
