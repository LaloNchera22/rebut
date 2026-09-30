//! `verifier-fabric`: where hostile PR code runs.
//!
//! * [`FirecrackerExecutor`] — production: one jailed, network-less,
//!   ephemeral Firecracker microVM per [`ExecutionRequest`](verifier_core::ExecutionRequest),
//!   optionally restored from a warm [`SnapshotCache`] snapshot.
//! * [`LocalProcessExecutor`] — **insecure**, development only: same guest
//!   logic, run directly on the host.
//!
//! # Layout
//!
//! The wire protocol and the step runner live in `verifier-guest`, which has
//! no dependency on this crate. The fabric depends on the guest library for
//! the protocol types/codec (re-exported as [`protocol`]) and, in the local
//! executor, to run the guest session in-process. No dependency cycle, and
//! the in-VM binary carries no host-side code.
//!
//! # Sealed requests
//!
//! The fabric returns full outputs of sealed requests to its caller (the
//! control plane); hiding them from contributors is enforced solely by
//! `verifier_core::Verdict::for_contributor`. The fabric itself must never
//! write sealed outputs anywhere else: step logging is centralized in the
//! session module and emits only the step index for sealed requests, the
//! guest never logs step output, and the VM console is discarded.

pub mod firecracker;
pub mod local;
pub mod session;
pub mod snapshot;
pub mod source;

pub use firecracker::{FirecrackerConfig, FirecrackerExecutor};
pub use local::LocalProcessExecutor;
pub use snapshot::{SnapshotCache, SnapshotEntry, SnapshotKey};
pub use source::{DirectorySource, SourceProvider, TarballSource};
pub use verifier_guest::protocol;
