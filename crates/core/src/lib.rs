//! `selflock-core` — blocking engine for the SelfLock Windows port.
//!
//! This crate is a faithful re-implementation of the Objective-C logic found in the
//! original project (Block Management / Common folders), with a Windows
//! hosts/firewall backend.

pub mod apps;
pub mod blocklist_file;
pub mod cache;
pub mod cleaner;
pub mod common_subdomains;
pub mod elevation;
pub mod entry;
pub mod error;
pub mod firewall;
pub mod google;
pub mod hosts;
pub mod instance;
pub mod lock;
pub mod logging;
pub mod manager;
pub mod paths;
pub mod platform;
pub mod process;
pub mod resolve;
pub mod scheduler;
pub mod scraper;
pub mod security;
pub mod settings;

pub use entry::BlockEntry;
pub use error::{Error, Result};

/// Version string reported by the CLI, mirroring `SELFLOCK_VERSION_STRING`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
