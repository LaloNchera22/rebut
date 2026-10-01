//! Library behind the `rebut` command and the MCP server.
//!
//! Everything here is something a contributor or auditor can do without
//! trusting the operator: run the public checks on their own code, recompute
//! a seed from drand, regenerate public challenges, and verify a receipt.

pub mod audit;
pub mod local;

pub use audit::{derive_seed, regenerate_challenges, verify_receipt, ReceiptCheck, SeedInfo};
pub use local::{verify_local, LocalOptions};
