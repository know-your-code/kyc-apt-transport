//! Library half of `apt-transport-kyc`. Two consumers:
//!
//! - `kyc-cli` (the `kyc` binary) uses [`device_flow::run`] to back
//!   `kyc license sso`. It enables the `cli-ui` feature so the
//!   browser-launch branch is wired in.
//! - The `apt-transport-kyc` binary in this crate uses [`device_flow::run`]
//!   on the first license-gated request, alongside [`protocol`] (APT method
//!   protocol parser/emitter) and [`license_store`] (read/write
//!   `~/.kyc/license` with the SUDO_USER fallback policy).
//!
//! The library half deliberately stays stdlib + reqwest only; no
//! `kyc-license`, no `kyc-storage`, no workspace-internal dependencies.
//! That keeps this crate cleanly publishable and lets `kyc-cli` consume
//! it via a `git=` dependency.

pub mod device_flow;
pub mod license_store;
pub mod protocol;
