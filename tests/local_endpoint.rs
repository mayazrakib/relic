#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::Path;

use relic::local_endpoint::{
    EndpointError, FileIdentity, LocalEndpoint, get_disjoint_scope_evidence,
};

fn get_identity(path: &Path) -> FileIdentity {
    let metadata = fs::metadata(path).unwrap();
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[test]
fn pins_identity_reports_capacity_and_rejects_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let parent = fs::canonicalize(directory.path()).unwrap();
    let path = parent.join("source");
    fs::create_dir(&path).unwrap();
    let identity = get_identity(&path);
    let endpoint = LocalEndpoint::resolve(&path, identity).unwrap();
    assert_eq!(endpoint.identity(), identity);
    let capacity = endpoint.capacity().unwrap();
    assert!(capacity.available_bytes <= capacity.capacity_bytes);
    fs::rename(&path, parent.join("old")).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(matches!(
        endpoint.revalidate(),
        Err(EndpointError::IDENTITY_CHANGED)
    ));
    assert!(matches!(
        LocalEndpoint::resolve(&path, identity),
        Err(EndpointError::IDENTITY_CHANGED)
    ));
}

#[test]
fn rejects_symlink_components_and_ancestor_overlap() {
    let directory = tempfile::tempdir().unwrap();
    let parent = fs::canonicalize(directory.path()).unwrap();
    let source = parent.join("source");
    let nested = source.join("nested");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&nested).unwrap();
    let source_endpoint = LocalEndpoint::resolve(&source, get_identity(&source)).unwrap();
    let nested_endpoint = LocalEndpoint::resolve(&nested, get_identity(&nested)).unwrap();
    assert!(matches!(
        get_disjoint_scope_evidence(&[&source_endpoint, &nested_endpoint]),
        Err(EndpointError::OVERLAP)
    ));
    let alias = parent.join("alias");
    symlink(&source, &alias).unwrap();
    assert!(LocalEndpoint::resolve(&alias, get_identity(&source)).is_err());
    assert!(LocalEndpoint::resolve(&alias.join("nested"), get_identity(&nested)).is_err());
}

#[test]
fn sibling_scopes_are_emitted_only_with_sufficient_mount_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let parent = fs::canonicalize(directory.path()).unwrap();
    let left = parent.join("left");
    let right = parent.join("right");
    fs::create_dir(&left).unwrap();
    fs::create_dir(&right).unwrap();
    let left_endpoint = LocalEndpoint::resolve(&left, get_identity(&left)).unwrap();
    let right_endpoint = LocalEndpoint::resolve(&right, get_identity(&right)).unwrap();
    match get_disjoint_scope_evidence(&[&left_endpoint, &right_endpoint]) {
        Ok(scopes) => {
            assert!(left_endpoint.mount_id().is_some());
            assert_eq!(left_endpoint.mount_id(), right_endpoint.mount_id());
            assert_ne!(scopes[0].domain, scopes[1].domain);
        }
        Err(EndpointError::AMBIGUOUS_SCOPE) => assert!(
            left_endpoint.mount_id().is_none()
                || left_endpoint.mount_id() != right_endpoint.mount_id()
        ),
        Err(error) => panic!("unexpected endpoint error: {error}"),
    }
}
