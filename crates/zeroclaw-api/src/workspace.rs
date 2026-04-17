//! Shared workspace directory layout.
//!
//! Subpaths below the ZeroClaw workspace root. Consumers build absolute
//! paths with `workspace_dir.join(<CONST>)`. Putting them here keeps
//! callers in different crates (channel persistence, sandbox mounting)
//! from drifting apart.

use std::path::{Path, PathBuf};

/// Top-level bucket for data the agent reads or writes during a session.
pub const DATA_SUBDIR: &str = "data";

/// Inbound attachments saved from Signal. Mounted read-only into the
/// shell sandbox so the agent can inspect them but cannot mutate them.
pub const SIGNAL_INBOUND_SUBDIR: &str = "data/signal_inbound";

/// Scratch dir the agent can write into from the sandboxed shell.
/// Files placed here are reachable by channel marker resolvers
/// (e.g. `[IMAGE:<workspace>/data/agent_outbox/foo.jpg]`).
pub const AGENT_OUTBOX_SUBDIR: &str = "data/agent_outbox";

pub fn signal_inbound_dir(workspace: &Path) -> PathBuf {
    workspace.join(SIGNAL_INBOUND_SUBDIR)
}

pub fn agent_outbox_dir(workspace: &Path) -> PathBuf {
    workspace.join(AGENT_OUTBOX_SUBDIR)
}
