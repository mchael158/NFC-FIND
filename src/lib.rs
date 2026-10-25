//! NFC-FIND core library.
//!
//! `#![no_std]`-capable (requires `alloc`). Contains the portable protocol,
//! traits, and synchronous relay logic usable on desktop and embedded targets
//! (e.g. ESP32). Platform-specific I/O lives in the binary / board support.

#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod core;

#[cfg(feature = "alloc")]
pub use core::*;

#[cfg(feature = "cli")]
pub mod auth;
#[cfg(feature = "cli")]
pub mod net;
#[cfg(feature = "cli")]
pub mod nfc;
#[cfg(feature = "cli")]
pub mod relay;
