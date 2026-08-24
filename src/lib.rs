//! Autonomous Software Factory control-plane library.
//!
//! ASF owns durable work obligations. Execution is delegated to Runmill and
//! provider identity is delegated to ctxlane. The types in [`contracts`] form
//! the signed boundary between those systems.

pub mod adapters;
pub mod api;
pub mod application;
pub mod artifacts;
pub mod audit;
pub mod auth;
pub mod config;
pub mod contracts;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod ledger;
pub mod ports;
pub mod runtime;
pub mod security;

pub use error::{Error, Result};
