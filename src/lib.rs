pub mod archive;
#[cfg(feature = "embedded-archive")]
pub mod archive_backend;
#[cfg(all(feature = "embedded-archive", unix))]
pub mod archive_disk;
#[cfg(feature = "embedded-archive")]
pub mod archive_manifest;
#[cfg(all(feature = "embedded-archive", target_os = "linux"))]
pub mod archive_snapshot;
#[cfg(feature = "embedded-archive")]
pub mod archive_source;
#[cfg(all(feature = "embedded-archive", unix))]
pub mod archive_worker;
pub mod artifact_store;
pub mod config;
pub mod contracts;
pub mod domain;
#[cfg(feature = "embedded-archive")]
pub mod embedded_archive;
pub mod encrypted_manifest_sort;
pub mod encrypted_spool;
pub mod gateway_layout;
pub mod gateway_state;
#[cfg(all(feature = "embedded-archive", target_os = "linux"))]
pub mod gateway_store;
#[cfg(all(feature = "embedded-archive", target_os = "linux"))]
pub mod gateway_worker;
pub mod identity;
pub mod local_endpoint;
pub mod manifest;
pub mod manifest_artifact;
pub mod manifest_spool;
#[cfg(all(feature = "embedded-archive", target_os = "linux"))]
pub mod native_run_store;
pub mod payload_capture;
#[cfg(target_os = "linux")]
pub mod physical_registry;
pub mod planner;
pub mod resources;
pub mod restore;
pub mod restore_store;
pub mod scheduler;
pub mod service;
pub mod source_scan;
pub mod staging_quota;
pub mod state;
pub mod volume_budget;
pub mod worker_identity;
pub mod worker_runtime;
pub mod worker_state;

#[cfg(target_os = "linux")]
mod worker_sandbox;
