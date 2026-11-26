use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum ArchiveError {
    Io(io::Error),
    InvalidInput,
    OutputLimit,
    OutcomeUnknown,
    CommandFailed,
    InvalidOutput,
    Conflict,
}

impl From<io::Error> for ArchiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Deserialize)]
pub struct Snapshot {
    pub id: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

pub struct Archive {
    pub executable: PathBuf,
    pub repository: PathBuf,
    pub password_file: PathBuf,
    pub timeout: Duration,
}

fn read_output(mut input: impl Read) -> io::Result<(Vec<u8>, bool)> {
    let mut result = Vec::new();
    let mut buffer = [0; 8192];
    let mut is_truncated = false;

    loop {
        let count = input.read(&mut buffer)?;

        if count == 0 {
            break;
        }

        let available = MAX_OUTPUT_BYTES.saturating_sub(result.len());
        result.extend_from_slice(&buffer[..count.min(available)]);
        is_truncated |= count > available;
    }

    Ok((result, is_truncated))
}

fn validate_token(value: &str) -> Result<(), ArchiveError> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ArchiveError::InvalidInput);
    }

    Ok(())
}

impl Archive {
    fn run(&self, arguments: &[OsString], is_write: bool) -> Result<Vec<u8>, ArchiveError> {
        let mut child = Command::new(&self.executable)
            .arg("--repo")
            .arg(&self.repository)
            .arg("--password-file")
            .arg(&self.password_file)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child.stdout.take().ok_or(ArchiveError::InvalidOutput)?;
        let stderr = child.stderr.take().ok_or(ArchiveError::InvalidOutput)?;
        let stdout_reader = thread::spawn(move || read_output(stdout));
        let stderr_reader = thread::spawn(move || read_output(stderr));
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }

            if started.elapsed() >= self.timeout {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }

            thread::sleep(Duration::from_millis(10));
        };
        let (output, is_output_truncated) = stdout_reader
            .join()
            .map_err(|_| ArchiveError::InvalidOutput)??;
        let (_, is_error_truncated) = stderr_reader
            .join()
            .map_err(|_| ArchiveError::InvalidOutput)??;

        if status.is_none() || ((is_output_truncated || is_error_truncated) && is_write) {
            return Err(ArchiveError::OutcomeUnknown);
        }

        if is_output_truncated || is_error_truncated {
            return Err(ArchiveError::OutputLimit);
        }

        if !status.ok_or(ArchiveError::InvalidOutput)?.success() {
            return Err(if is_write {
                ArchiveError::OutcomeUnknown
            } else {
                ArchiveError::CommandFailed
            });
        }

        Ok(output)
    }

    pub fn initialize(&self) -> Result<(), ArchiveError> {
        self.run(
            &["init".into(), "--repository-version".into(), "2".into()],
            true,
        )?;
        Ok(())
    }

    pub fn lookup(&self, key: &str, payload: &str) -> Result<Option<String>, ArchiveError> {
        validate_token(key)?;
        validate_token(payload)?;
        let output = self.run(&["snapshots".into(), "--json".into()], false)?;
        let snapshots: Vec<Snapshot> =
            serde_json::from_slice(&output).map_err(|_| ArchiveError::InvalidOutput)?;
        let key_tag = format!("relic-key-{key}");
        let payload_tag = format!("relic-payload-{payload}");
        let matches: Vec<&Snapshot> = snapshots
            .iter()
            .filter(|snapshot| snapshot.tags.contains(&key_tag))
            .collect();

        if matches
            .iter()
            .any(|snapshot| !snapshot.tags.contains(&payload_tag))
            || matches.len() > 1
        {
            return Err(ArchiveError::Conflict);
        }

        Ok(matches.first().map(|snapshot| snapshot.id.clone()))
    }

    pub fn backup(&self, source: &Path, key: &str, payload: &str) -> Result<String, ArchiveError> {
        if let Some(id) = self.lookup(key, payload)? {
            return Ok(id);
        }

        let arguments = [
            "backup".into(),
            "--json".into(),
            "--tag".into(),
            format!("relic-key-{key}").into(),
            "--tag".into(),
            format!("relic-payload-{payload}").into(),
            "--".into(),
            source.as_os_str().to_owned(),
        ];
        self.run(&arguments, true)?;
        self.lookup(key, payload)?
            .ok_or(ArchiveError::OutcomeUnknown)
    }

    pub fn restore(&self, snapshot: &str, destination: &Path) -> Result<(), ArchiveError> {
        validate_token(snapshot)?;

        if destination.exists() {
            return Err(ArchiveError::InvalidInput);
        }

        let arguments = [
            "restore".into(),
            snapshot.into(),
            "--target".into(),
            destination.as_os_str().to_owned(),
        ];
        self.run(&arguments, true)?;
        Ok(())
    }

    pub fn check(&self) -> Result<(), ArchiveError> {
        self.run(&["check".into(), "--read-data".into()], false)?;
        Ok(())
    }
}
