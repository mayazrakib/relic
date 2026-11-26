//! Durable identity of a worker's delegated kernel cgroup scope.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerIdentity {
    /// Domain-separated host marker; identical machine-id clones are not distinguished.
    pub host_id: String,
    pub boot_id: String,
    pub cgroup_namespace_inode: u64,
    /// Canonical absolute cgroup-relative path within this cgroup namespace.
    pub group_path: String,
    pub group_inode: u64,
    pub parent_path: String,
    pub parent_inode: u64,
}
