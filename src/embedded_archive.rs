use std::error::Error;
use std::fs;
use std::io;
use std::io::Read;
use std::path::Path;

use rustic_backend::BackendOptions;
use rustic_core::{
    BackupOptions, CheckOptions, ConfigOptions, Credentials, KeyOptions, LocalDestination,
    LsOptions, PathList, Repository, RepositoryOptions, RestoreOptions, SnapshotOptions,
};

fn get_path_text(path: &Path) -> Result<&str, io::Error> {
    path.to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not UTF-8"))
}

fn read_credentials(path: &Path) -> Result<Credentials, Box<dyn Error>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(4097).read_to_end(&mut bytes)?;

    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "invalid password file size").into(),
        );
    }

    let password = String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "password is not UTF-8"))?;
    let password = password.trim_end_matches(['\r', '\n']);

    if password.is_empty() || password.contains(['\r', '\n']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "password must be one nonempty line",
        )
        .into());
    }

    Ok(Credentials::password(password))
}

pub fn run_local_proof(
    repository: &Path,
    source: &Path,
    destination: &Path,
    password_file: &Path,
) -> Result<String, Box<dyn Error>> {
    if destination.exists() {
        return Err(
            io::Error::new(io::ErrorKind::AlreadyExists, "restore destination exists").into(),
        );
    }

    let credentials = read_credentials(password_file)?;
    let backends = BackendOptions::default()
        .repository(get_path_text(repository)?)
        .to_backends()?;
    let options = RepositoryOptions::default().no_cache(true);
    let config = ConfigOptions::default().set_version(2);
    let repository = Repository::new(&options, &backends)?.init(
        &credentials,
        &KeyOptions::default(),
        &config,
    )?;
    let repository = repository.to_indexed_ids()?;
    let paths: PathList = [source.to_path_buf()].into_iter().collect();
    let paths = paths.sanitize()?;
    let snapshot = SnapshotOptions::default().to_snapshot()?;
    let snapshot = repository.backup(&BackupOptions::default(), &paths, snapshot)?;
    let snapshot_id = snapshot.id.to_hex().as_str().to_owned();
    drop(repository);

    let repository = Repository::new(&options, &backends)?.open(&credentials)?;
    repository
        .check(CheckOptions::default().read_data(true))?
        .is_ok()?;
    let repository = repository.to_indexed()?;
    let node = repository.node_from_snapshot_path(&snapshot_id, |_| true)?;
    let listing_options = LsOptions::default();
    let listing = repository.ls(&node, &listing_options)?;
    let target = LocalDestination::new(get_path_text(destination)?, true, !node.is_dir())?;
    let restore_options = RestoreOptions::default();
    let plan = repository.prepare_restore(&restore_options, listing.clone(), &target, false)?;
    repository.restore(plan, &restore_options, listing, &target)?;
    Ok(snapshot_id)
}
