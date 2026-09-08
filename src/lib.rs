//! Reusable core for the single-BMC provisioning workflow.
//!
//! The library deliberately keeps credentials out of serializable result types.

pub mod lessor;
pub mod model;
pub mod redfish;
pub mod storage;
pub mod workflow;
