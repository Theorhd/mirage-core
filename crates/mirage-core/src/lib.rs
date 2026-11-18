//! Pure Sans-I/O protocol core for `mirage-core`.
//!
//! This crate contains zero network or filesystem I/O. All parsers and state
//! machines operate deterministically over caller-supplied byte slices.

#![forbid(unsafe_code)]

extern crate alloc;

pub mod crypto;
pub mod reality;
pub mod tls_parser;
