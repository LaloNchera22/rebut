//! `verifier-guest`: the agent that runs inside each Firecracker microVM.
//!
//! Layout decision: this crate owns the host/guest [`protocol`] and the step
//! [`runner`], and has no dependency on the fabric. `verifier-fabric` depends
//! on this library for the protocol (host side of the session) and to run
//! [`serve::serve_connection`] in-process for its insecure development
//! executor. The guest binary therefore stays small and free of any
//! host-only code (jailer, Firecracker API, snapshot cache).
//!
//! Modules:
//! * [`protocol`]: length-prefixed JSON frames and the message types.
//! * [`archive`]: deterministic source packing and hostile-tarball unpacking.
//! * [`runner`]: deterministic execution of `Build`/`Test`/`Harness` steps.
//! * [`serve`]: one guest session over any `AsyncRead`/`AsyncWrite`.

pub mod archive;
pub mod protocol;
pub mod runner;
pub mod serve;

pub use runner::{run_request, Runner};
pub use serve::serve_connection;
