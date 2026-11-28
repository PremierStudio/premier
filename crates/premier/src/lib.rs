//! Premier: Git-compatible source control with path and branch confidentiality,
//! capability-proxied secrets, and AI-agent sandboxing.
//!
//! This crate re-exports the Premier library crates under one name. The `premier`
//! command-line tool is published separately as [`premier-cli`](https://crates.io/crates/premier-cli).
//!
//! See <https://github.com/PremierStudio/premier> for documentation.
#![forbid(unsafe_code)]

pub use premier_core;
pub use premier_git_bridge;
pub use premier_overlay;
pub use premier_policy;
pub use premier_proxy;
pub use premier_secrets;
pub use premier_server;
pub use premier_ssh;
pub use premier_trace;
