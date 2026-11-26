use std::fmt;
#[cfg(not(target_os = "linux"))]
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(not(target_os = "linux"))]
use crate::resources::StageGuard;

#[derive(Clone, Copy)]
pub struct WorkerLimits {
    pub memory_max_bytes: u64,
    pub memory_high_bytes: u64,
    pub max_tasks: u64,
    pub max_open_files: u64,
    pub max_runtime: Duration,
    pub max_output_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum WorkerStopReason {
    MEMORY_LIMIT,
    CANCELED,
    DEADLINE,
    OUTPUT_LIMIT,
    PROCESS_FAILURE,
    PIPE_FAILURE,
    UNREAPED,
    EVIDENCE_FAILURE,
}

#[derive(Debug)]
pub struct WorkerStop {
    pub reason: WorkerStopReason,
    pub exit_code: Option<i32>,
    #[cfg(target_os = "linux")]
    pub recovery: Option<Box<PendingWorker>>,
    pub memory_peak_bytes: u64,
    pub memory_limit_events: u64,
}

#[derive(Debug)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum WorkerError {
    INVALID,
    UNSUPPORTED,
    CANCELED,
    DEADLINE,
    SPAWN,
    OUTCOME_UNKNOWN(WorkerStop),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::INVALID => "invalid worker execution request",
            Self::UNSUPPORTED => "worker containment is unavailable",
            Self::CANCELED => "worker execution stopped before launch",
            Self::DEADLINE => "worker deadline expired before launch",
            Self::SPAWN => "contained worker did not launch",
            Self::OUTCOME_UNKNOWN(_) => "worker effects require reconciliation",
        })
    }
}

impl std::error::Error for WorkerError {}

pub struct WorkerOutput {
    pub stdout: Vec<u8>,
    pub memory_peak_bytes: u64,
    pub memory_limit_events: u64,
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::os::unix::process::CommandExt;
    use std::path::{Component, Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use zeroize::Zeroizing;

    use super::{WorkerError, WorkerLimits, WorkerOutput, WorkerStop, WorkerStopReason};
    use crate::resources::{ResourceError, StageGuard};
    use crate::worker_identity::WorkerIdentity;
    use crate::worker_sandbox::WorkerSandbox;

    const MIB: u64 = 1024 * 1024;
    const MAX_PARENT_MEMORY_BYTES: u64 = 1024 * MIB;
    const MAX_PARENT_HIGH_BYTES: u64 = 768 * MIB;
    const MAX_WORKER_MEMORY_BYTES: u64 = 256 * MIB;
    const MIN_WORKER_MEMORY_BYTES: u64 = 16 * MIB;
    const MAX_INPUT_BYTES: usize = 64 * 1024 + 4;
    const MAX_OUTPUT_BYTES: usize = 64 * 1024;
    const POLL_INTERVAL: Duration = Duration::from_millis(5);
    const REAP_TIMEOUT: Duration = Duration::from_secs(2);
    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    const CGROUP2_MAGIC: libc::c_long = 0x63677270;

    fn parse_event_counter(text: &str, key: &str) -> Result<u64, WorkerError> {
        let mut found = None;
        for line in text.lines() {
            if let Some((name, value)) = line.split_once(' ')
                && name == key
            {
                if found.is_some() {
                    return Err(WorkerError::UNSUPPORTED);
                }
                found = Some(value.parse::<u64>().map_err(|_| WorkerError::UNSUPPORTED)?);
            }
        }
        found.ok_or(WorkerError::UNSUPPORTED)
    }

    fn read_counter(path: &Path) -> Result<u64, WorkerError> {
        let mut file = File::open(path).map_err(|_| WorkerError::UNSUPPORTED)?;
        let mut bytes = [0; 64];
        let count = file
            .read(&mut bytes)
            .map_err(|_| WorkerError::UNSUPPORTED)?;
        if count == bytes.len() {
            return Err(WorkerError::UNSUPPORTED);
        }
        std::str::from_utf8(&bytes[..count])
            .map_err(|_| WorkerError::UNSUPPORTED)?
            .trim()
            .parse()
            .map_err(|_| WorkerError::UNSUPPORTED)
    }

    fn get_membership() -> Result<PathBuf, WorkerError> {
        let text = fs::read_to_string("/proc/self/cgroup").map_err(|_| WorkerError::UNSUPPORTED)?;
        let membership = text
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or(WorkerError::UNSUPPORTED)?;
        let path = Path::new(membership);
        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        let path = Path::new("/sys/fs/cgroup").join(
            path.strip_prefix("/")
                .map_err(|_| WorkerError::UNSUPPORTED)?,
        );
        let directory = File::open(&path).map_err(|_| WorkerError::UNSUPPORTED)?;
        let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: directory is live and info points to writable statfs storage.
        if unsafe { libc::fstatfs(directory.as_raw_fd(), info.as_mut_ptr()) } != 0 {
            return Err(WorkerError::UNSUPPORTED);
        }
        // SAFETY: successful fstatfs initialized info.
        if unsafe { info.assume_init() }.f_type != CGROUP2_MAGIC {
            return Err(WorkerError::UNSUPPORTED);
        }
        Ok(path)
    }

    // This is a local continuity marker, not attestation; cloned machine IDs
    // must not be used concurrently as independent hosts.
    fn get_host_id() -> Result<String, WorkerError> {
        use sha2::{Digest, Sha256};
        let file = File::open("/etc/machine-id").map_err(|_| WorkerError::UNSUPPORTED)?;
        let mut input = Vec::with_capacity(34);
        file.take(34)
            .read_to_end(&mut input)
            .map_err(|_| WorkerError::UNSUPPORTED)?;
        if input.len() != 32 && !(input.len() == 33 && input[32] == b'\n') {
            return Err(WorkerError::UNSUPPORTED);
        }
        let id = &input[..32];
        if !id
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            || id.iter().all(|byte| *byte == b'0')
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        let mut digest = Sha256::new();
        digest.update(b"relic/worker-host/v1\0");
        digest.update(id);
        let encoded: String = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(format!("sha256:{encoded}"))
    }

    fn get_boot_id() -> Result<String, WorkerError> {
        let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|_| WorkerError::UNSUPPORTED)?;
        let text = value.trim();
        let parsed = uuid::Uuid::parse_str(text).map_err(|_| WorkerError::UNSUPPORTED)?;
        if parsed.to_string() != text {
            return Err(WorkerError::UNSUPPORTED);
        }
        Ok(text.to_owned())
    }

    fn get_namespace_inode() -> Result<u64, WorkerError> {
        let value = fs::metadata("/proc/self/ns/cgroup")
            .map_err(|_| WorkerError::UNSUPPORTED)?
            .ino();
        if value == 0 {
            return Err(WorkerError::UNSUPPORTED);
        }
        Ok(value)
    }

    fn get_cgroup_relative(path: &Path) -> Result<String, WorkerError> {
        let relative = path
            .strip_prefix("/sys/fs/cgroup")
            .map_err(|_| WorkerError::UNSUPPORTED)?;
        let path = Path::new("/").join(relative);
        if path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        path.to_str()
            .map(str::to_owned)
            .ok_or(WorkerError::UNSUPPORTED)
    }

    fn validate_worker_path(group: &str, parent: &str) -> Result<(), WorkerError> {
        let group = Path::new(group);
        let parent = Path::new(parent);
        for path in [group, parent] {
            let mut canonical = PathBuf::new();
            for component in path.components() {
                canonical.push(component.as_os_str());
            }
            if canonical.as_os_str() != path.as_os_str() {
                return Err(WorkerError::UNSUPPORTED);
            }
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
                || path.to_str().is_none_or(|text| text.len() > 4096)
            {
                return Err(WorkerError::UNSUPPORTED);
            }
        }
        if group.parent() != Some(parent) {
            return Err(WorkerError::UNSUPPORTED);
        }
        let name = group
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(WorkerError::UNSUPPORTED)?;
        let suffix = name
            .strip_prefix("worker_")
            .ok_or(WorkerError::UNSUPPORTED)?;
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        Ok(())
    }

    fn check_cgroup_directory(directory: &File) -> Result<(), WorkerError> {
        let metadata = directory.metadata().map_err(|_| WorkerError::UNSUPPORTED)?;
        // SAFETY: geteuid is a scalar identity query.
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(WorkerError::UNSUPPORTED);
        }
        let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: directory is live and info is writable.
        if unsafe { libc::fstatfs(directory.as_raw_fd(), info.as_mut_ptr()) } != 0 {
            return Err(WorkerError::UNSUPPORTED);
        }
        // SAFETY: successful fstatfs initialized info.
        if unsafe { info.assume_init() }.f_type != CGROUP2_MAGIC {
            return Err(WorkerError::UNSUPPORTED);
        }
        Ok(())
    }

    fn open_directory_nofollow(path: &Path) -> Result<File, WorkerError> {
        use std::os::fd::FromRawFd;
        use std::os::unix::ffi::OsStrExt;
        let text = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| WorkerError::UNSUPPORTED)?;
        // SAFETY: path is NUL-terminated and flags prevent final symlink traversal.
        let fd = unsafe {
            libc::open(
                text.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(WorkerError::UNSUPPORTED);
        }
        // SAFETY: fd is newly owned.
        let file = unsafe { File::from_raw_fd(fd) };
        check_cgroup_directory(&file)?;
        Ok(file)
    }

    fn get_group_identity(path: &Path) -> Result<WorkerIdentity, WorkerError> {
        let parent = path.parent().ok_or(WorkerError::UNSUPPORTED)?;
        let group_path = get_cgroup_relative(path)?;
        let parent_path = get_cgroup_relative(parent)?;
        validate_worker_path(&group_path, &parent_path)?;
        let membership = get_membership()?;
        if membership != path
            && !(membership
                .file_name()
                .is_some_and(|name| name == "supervisor")
                && membership.parent() == Some(parent))
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        let group = open_directory_nofollow(path)?;
        let parent = open_directory_nofollow(parent)?;
        Ok(WorkerIdentity {
            host_id: get_host_id()?,
            boot_id: get_boot_id()?,
            cgroup_namespace_inode: get_namespace_inode()?,
            group_path,
            group_inode: group
                .metadata()
                .map_err(|_| WorkerError::UNSUPPORTED)?
                .ino(),
            parent_path,
            parent_inode: parent
                .metadata()
                .map_err(|_| WorkerError::UNSUPPORTED)?
                .ino(),
        })
    }

    pub fn get_current_worker_identity() -> Result<WorkerIdentity, WorkerError> {
        get_group_identity(&get_membership()?)
    }

    pub fn verify_current_worker_identity(expected: &WorkerIdentity) -> Result<(), WorkerError> {
        if &get_current_worker_identity()? != expected {
            return Err(WorkerError::UNSUPPORTED);
        }
        Ok(())
    }

    fn prove_removed_original(
        parent: &File,
        name: &std::ffi::CStr,
        original: &File,
        events: Option<&File>,
    ) -> Result<bool, WorkerError> {
        let is_offline = if let Some(events) = events {
            let mut probe = [0u8; 1];
            match events.read_at(&mut probe, 0) {
                Err(error) if error.raw_os_error() == Some(libc::ENODEV) => true,
                Ok(_) => false,
                Err(_) => return Err(WorkerError::UNSUPPORTED),
            }
        } else {
            original
                .metadata()
                .map_err(|_| WorkerError::UNSUPPORTED)?
                .nlink()
                == 0
        };
        if !is_offline {
            return Ok(false);
        }
        let mut slot = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: parent, single component and output storage are live.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                slot.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            // Any replacement or unexpected surviving name is not proof of absence.
            return Err(WorkerError::UNSUPPORTED);
        }
        match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::NotFound => Ok(true),
            _ => Err(WorkerError::UNSUPPORTED),
        }
    }

    /// Quiescence after a boot change only proves local processes and cgroup handles
    /// cannot survive under the exclusive local-filesystem/no-migration assumption;
    /// it is not proof about remote storage, quorum replacement, or cloned host IDs.
    /// Same-boot absent paths assume the delegated scope cannot be renamed or migrated
    /// by workers and no external controller recreates its UUID names.
    pub fn quiesce_recorded_worker(
        identity: &WorkerIdentity,
        guard: &StageGuard,
    ) -> Result<bool, WorkerError> {
        use std::os::fd::FromRawFd;
        validate_worker_path(&identity.group_path, &identity.parent_path)?;
        if identity.group_inode == 0
            || identity.parent_inode == 0
            || identity.cgroup_namespace_inode == 0
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        let recorded_boot =
            uuid::Uuid::parse_str(&identity.boot_id).map_err(|_| WorkerError::UNSUPPORTED)?;
        if recorded_boot.to_string() != identity.boot_id {
            return Err(WorkerError::UNSUPPORTED);
        }
        guard.check().map_err(|_| WorkerError::CANCELED)?;
        if get_host_id()? != identity.host_id {
            return Err(WorkerError::UNSUPPORTED);
        }
        if get_boot_id()? != identity.boot_id {
            return Ok(true);
        }
        if get_namespace_inode()? != identity.cgroup_namespace_inode {
            return Err(WorkerError::UNSUPPORTED);
        }
        let membership = get_membership()?;
        if membership
            .file_name()
            .is_none_or(|name| name != "supervisor")
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        let parent_path = membership.parent().ok_or(WorkerError::UNSUPPORTED)?;
        if get_cgroup_relative(parent_path)? != identity.parent_path {
            return Err(WorkerError::UNSUPPORTED);
        }
        let parent = open_directory_nofollow(parent_path)?;
        let name = Path::new(&identity.group_path)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(WorkerError::UNSUPPORTED)?;
        let name = std::ffi::CString::new(name).map_err(|_| WorkerError::UNSUPPORTED)?;
        // SAFETY: parent and NUL-terminated single component are valid.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                return Ok(true);
            }
            return Err(WorkerError::UNSUPPORTED);
        }
        // SAFETY: fd is newly owned.
        let group = unsafe { File::from_raw_fd(fd) };
        check_cgroup_directory(&group)?;
        let group_metadata = group.metadata().map_err(|_| WorkerError::UNSUPPORTED)?;
        let parent_metadata = parent.metadata().map_err(|_| WorkerError::UNSUPPORTED)?;
        if parent_metadata.ino() != identity.parent_inode
            || group_metadata.ino() != identity.group_inode
            || group_metadata.dev() != parent_metadata.dev()
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        // Open events before kill so concurrent removal can be proved against the original kernfs node.
        // SAFETY: group is pinned and the name is a fixed component.
        let events_fd = unsafe {
            libc::openat(
                group.as_raw_fd(),
                c"cgroup.events".as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if events_fd < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                return prove_removed_original(&parent, &name, &group, None);
            }
            return Err(WorkerError::UNSUPPORTED);
        }
        // SAFETY: events_fd is newly owned.
        let events = unsafe { File::from_raw_fd(events_fd) };
        // SAFETY: group is pinned, component is fixed, and no-follow rejects symlinks.
        let kill_fd = unsafe {
            libc::openat(
                group.as_raw_fd(),
                c"cgroup.kill".as_ptr(),
                libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if kill_fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ENODEV)
            {
                return prove_removed_original(&parent, &name, &group, Some(&events));
            }
            return Ok(false);
        }
        // SAFETY: kill_fd is newly owned.
        let mut kill = unsafe { File::from_raw_fd(kill_fd) };
        if let Err(error) = kill.write_all(b"1") {
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ENODEV)
            {
                return prove_removed_original(&parent, &name, &group, Some(&events));
            }
            return Ok(false);
        }
        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            guard.check().map_err(|_| WorkerError::CANCELED)?;
            let mut bytes = [0u8; 512];
            let count = match events.read_at(&mut bytes, 0) {
                Ok(count) => count,
                Err(error) if error.raw_os_error() == Some(libc::ENODEV) => {
                    return prove_removed_original(&parent, &name, &group, Some(&events));
                }
                Err(_) => return Err(WorkerError::UNSUPPORTED),
            };
            if count == bytes.len() {
                return Err(WorkerError::UNSUPPORTED);
            }
            let text =
                std::str::from_utf8(&bytes[..count]).map_err(|_| WorkerError::UNSUPPORTED)?;
            match parse_event_counter(text, "populated")? {
                0 => break,
                1 if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
                1 => return Ok(false),
                _ => return Err(WorkerError::UNSUPPORTED),
            }
        }
        let mut slot = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: parent, component and writable output storage are live.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                slot.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                return prove_removed_original(&parent, &name, &group, Some(&events));
            }
            return Ok(false);
        }
        // SAFETY: successful fstatat initialized slot.
        let slot = unsafe { slot.assume_init() };
        if slot.st_ino != identity.group_inode
            || slot.st_dev != parent_metadata.dev()
            || slot.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        // SAFETY: parent and fixed generated component are live.
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                return prove_removed_original(&parent, &name, &group, Some(&events));
            }
            return Ok(false);
        }
        let mut removed_slot = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: parent, component and output storage remain live.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                removed_slot.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
            return Ok(false);
        }
        Ok(true)
    }

    fn check_parent(path: &Path) -> Result<(), WorkerError> {
        if read_counter(&path.join("memory.max"))? > MAX_PARENT_MEMORY_BYTES
            || read_counter(&path.join("memory.high"))? > MAX_PARENT_HIGH_BYTES
            || read_counter(&path.join("memory.swap.max"))? != 0
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        let controllers = fs::read_to_string(path.join("cgroup.subtree_control"))
            .map_err(|_| WorkerError::UNSUPPORTED)?;
        if !["cpu", "memory", "pids"]
            .iter()
            .all(|name| controllers.split_whitespace().any(|item| item == *name))
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        Ok(())
    }

    pub fn verify_worker_envelope(memory_max_bytes: u64) -> Result<(), WorkerError> {
        if !(MIN_WORKER_MEMORY_BYTES..=MAX_WORKER_MEMORY_BYTES).contains(&memory_max_bytes) {
            return Err(WorkerError::INVALID);
        }
        let path = get_membership()?;
        if !path
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().starts_with(b"worker_"))
            || read_counter(&path.join("memory.max"))? != memory_max_bytes
            || read_counter(&path.join("memory.high"))? > memory_max_bytes * 3 / 4
            || read_counter(&path.join("memory.swap.max"))? != 0
            || read_counter(&path.join("pids.max"))? > 64
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        let cpu = fs::read_to_string(path.join("cpu.max")).map_err(|_| WorkerError::UNSUPPORTED)?;
        if cpu.trim() != "100000 100000" {
            return Err(WorkerError::UNSUPPORTED);
        }
        // SAFETY: these scalar queries do not retain pointers or mutate process state.
        if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
            || unsafe { libc::prctl(libc::PR_GET_SECCOMP) } != 2
        {
            return Err(WorkerError::UNSUPPORTED);
        }
        let mut core = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // SAFETY: core is writable rlimit storage for this synchronous query.
        if unsafe { libc::getrlimit(libc::RLIMIT_CORE, core.as_mut_ptr()) } != 0 {
            return Err(WorkerError::UNSUPPORTED);
        }
        // SAFETY: successful getrlimit initialized core.
        let core = unsafe { core.assume_init() };
        if core.rlim_cur != 0 || core.rlim_max != 0 {
            return Err(WorkerError::UNSUPPORTED);
        }
        check_parent(path.parent().ok_or(WorkerError::UNSUPPORTED)?)
    }

    pub fn prepare_worker_process() -> Result<(), WorkerError> {
        let membership = get_membership()?;
        verify_worker_envelope(read_counter(&membership.join("memory.max"))?)?;
        // SAFETY: this scalar-only prctl disables external same-user process inspection.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(WorkerError::UNSUPPORTED);
        }
        Ok(())
    }

    struct WorkerGroup {
        path: PathBuf,
        directory: File,
        events: File,
    }

    impl WorkerGroup {
        fn create(limits: WorkerLimits) -> Result<Self, WorkerError> {
            let membership = get_membership()?;
            if membership
                .file_name()
                .is_none_or(|name| name != "supervisor")
            {
                return Err(WorkerError::UNSUPPORTED);
            }
            let parent = membership.parent().ok_or(WorkerError::UNSUPPORTED)?;
            check_parent(parent)?;
            let path = parent.join(format!("worker_{}", uuid::Uuid::now_v7().simple()));
            fs::create_dir(&path).map_err(|_| WorkerError::UNSUPPORTED)?;
            let directory = match open_directory_nofollow(&path) {
                Ok(directory) => directory,
                Err(error) => {
                    let _ = fs::remove_dir(&path);
                    return Err(error);
                }
            };
            // SAFETY: directory is pinned and the event name is a fixed component.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    c"cgroup.events".as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let _ = fs::remove_dir(&path);
                return Err(WorkerError::UNSUPPORTED);
            }
            // SAFETY: fd is newly owned and close-on-exec.
            let events = unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) };
            let group = Self {
                path,
                directory,
                events,
            };
            for (name, value) in [
                ("memory.max", limits.memory_max_bytes),
                ("memory.high", limits.memory_high_bytes),
                ("memory.swap.max", 0),
                ("memory.oom.group", 1),
                ("pids.max", limits.max_tasks),
            ] {
                fs::write(group.path.join(name), value.to_string())
                    .map_err(|_| WorkerError::UNSUPPORTED)?;
                if read_counter(&group.path.join(name))? != value {
                    return Err(WorkerError::UNSUPPORTED);
                }
            }
            fs::write(group.path.join("cpu.max"), "100000 100000")
                .map_err(|_| WorkerError::UNSUPPORTED)?;
            Ok(group)
        }

        fn is_populated(&self) -> Result<bool, WorkerError> {
            let mut bytes = [0u8; 256];
            let count = match self.events.read_at(&mut bytes, 0) {
                Ok(count) => count,
                Err(error) if error.raw_os_error() == Some(libc::ENODEV) => return Ok(false),
                Err(_) => return Err(WorkerError::UNSUPPORTED),
            };
            if count == bytes.len() {
                return Err(WorkerError::UNSUPPORTED);
            }
            let text =
                std::str::from_utf8(&bytes[..count]).map_err(|_| WorkerError::UNSUPPORTED)?;
            match parse_event_counter(text, "populated")? {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(WorkerError::UNSUPPORTED),
            }
        }

        fn kill(&self) {
            use std::os::fd::FromRawFd;
            // SAFETY: directory is pinned to the original scope and name is fixed.
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    c"cgroup.kill".as_ptr(),
                    libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd >= 0 {
                // SAFETY: fd is newly owned.
                let mut file = unsafe { File::from_raw_fd(fd) };
                let _ = file.write_all(b"1");
            }
        }

        fn get_peak_bytes(&self) -> Result<u64, WorkerError> {
            read_counter(&self.path.join("memory.peak"))
        }

        fn get_memory_events(&self) -> Result<u64, WorkerError> {
            let text = fs::read_to_string(self.path.join("memory.events"))
                .map_err(|_| WorkerError::UNSUPPORTED)?;
            parse_event_counter(&text, "oom_kill")
        }

        fn get_stop(&self, reason: WorkerStopReason) -> WorkerError {
            let peak = self.get_peak_bytes();
            let events = self.get_memory_events();
            let reason = if peak.is_err() || events.is_err() {
                WorkerStopReason::EVIDENCE_FAILURE
            } else if events.as_ref().is_ok_and(|count| *count > 0) {
                WorkerStopReason::MEMORY_LIMIT
            } else {
                reason
            };
            WorkerError::OUTCOME_UNKNOWN(WorkerStop {
                reason,
                exit_code: None,
                recovery: None,
                memory_peak_bytes: peak.unwrap_or(0),
                memory_limit_events: events.unwrap_or(0),
            })
        }
    }

    impl Drop for WorkerGroup {
        fn drop(&mut self) {
            if !matches!(self.is_populated(), Ok(false)) {
                self.kill();
            }
            if matches!(self.is_populated(), Ok(false)) {
                let pinned = self.directory.metadata();
                let slot = fs::symlink_metadata(&self.path);
                if let (Ok(pinned), Ok(slot)) = (pinned, slot)
                    && slot.is_dir()
                    && !slot.file_type().is_symlink()
                    && pinned.dev() == slot.dev()
                    && pinned.ino() == slot.ino()
                {
                    let _ = fs::remove_dir(&self.path);
                }
            }
        }
    }

    fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        // SAFETY: fd is a live pipe descriptor; fcntl does not retain pointers.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: preserve current flags while adding O_NONBLOCK to this descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn spawn_worker(
        executable: &Path,
        group: &WorkerGroup,
        limits: WorkerLimits,
        read_paths: &[PathBuf],
        write_paths: &[PathBuf],
    ) -> Result<Child, WorkerError> {
        let sandbox = WorkerSandbox::prepare(executable, read_paths, write_paths)
            .map_err(|_| WorkerError::UNSUPPORTED)?;
        let procs = OpenOptions::new()
            .write(true)
            .open(group.path.join("cgroup.procs"))
            .map_err(|_| WorkerError::UNSUPPORTED)?;
        let procs_fd = procs.as_raw_fd();
        // SAFETY: getpid has no arguments or memory safety preconditions.
        let parent_pid = unsafe { libc::getpid() };
        let mut command = Command::new(executable);
        command
            .env_clear()
            .env("RAYON_NUM_THREADS", "1")
            .env("TOKIO_WORKER_THREADS", "1")
            .env("LANG", "C.UTF-8")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: this closure uses only stack values and async-signal-safe syscalls.
        // Joining the capped group happens before exec, so no worker code runs outside it.
        unsafe {
            command.pre_exec(move || {
                let pid = libc::getpid() as u32;
                let mut bytes = [0_u8; 16];
                let mut value = pid;
                let mut position = bytes.len();
                loop {
                    position -= 1;
                    bytes[position] = b'0' + (value % 10) as u8;
                    value /= 10;
                    if value == 0 {
                        break;
                    }
                }
                let length = bytes.len() - position;
                if libc::write(procs_fd, bytes[position..].as_ptr().cast(), length)
                    != length as isize
                {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent_pid
                {
                    return Err(io::Error::from_raw_os_error(libc::ECHILD));
                }
                let descriptor_limit = libc::rlimit {
                    rlim_cur: limits.max_open_files,
                    rlim_max: limits.max_open_files,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &descriptor_limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let core_limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &core_limit) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                let header = CapabilityHeader {
                    version: 0x20080522,
                    pid: 0,
                };
                let data = [
                    CapabilityData {
                        effective: 0,
                        permitted: 0,
                        inheritable: 0,
                    },
                    CapabilityData {
                        effective: 0,
                        permitted: 0,
                        inheritable: 0,
                    },
                ];
                if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0
                    || libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_CLEAR_ALL,
                        0,
                        0,
                        0,
                    ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                sandbox.apply()?;
                Ok(())
            });
        }
        let child = command.spawn().map_err(|_| WorkerError::SPAWN)?;
        drop(procs);
        Ok(child)
    }

    pub struct PendingWorker {
        child: Child,
        group: WorkerGroup,
    }

    impl std::fmt::Debug for PendingWorker {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("PendingWorker")
                .field("pid", &self.child.id())
                .finish_non_exhaustive()
        }
    }

    impl PendingWorker {
        pub fn has_ended(&mut self) -> bool {
            self.child.try_wait().ok().flatten().is_some()
                && matches!(self.group.is_populated(), Ok(false))
        }

        pub fn try_reap(&mut self) -> bool {
            self.group.kill();
            let deadline = Instant::now() + REAP_TIMEOUT;
            while Instant::now() < deadline {
                if self.has_ended() {
                    return true;
                }
                thread::sleep(POLL_INTERVAL);
            }
            self.has_ended()
        }
    }

    impl Drop for PendingWorker {
        fn drop(&mut self) {
            self.group.kill();
            let _ = self.child.try_wait();
        }
    }

    fn stop_worker(mut child: Child, group: WorkerGroup, reason: WorkerStopReason) -> WorkerError {
        group.kill();
        let deadline = Instant::now() + REAP_TIMEOUT;
        while Instant::now() < deadline {
            let is_reaped = child.try_wait().ok().flatten().is_some();
            if is_reaped && matches!(group.is_populated(), Ok(false)) {
                let mut error = group.get_stop(reason);
                if let WorkerError::OUTCOME_UNKNOWN(stop) = &mut error {
                    stop.exit_code = child
                        .try_wait()
                        .ok()
                        .flatten()
                        .and_then(|status| status.code());
                }
                return error;
            }
            thread::sleep(POLL_INTERVAL);
        }
        let mut error = group.get_stop(WorkerStopReason::UNREAPED);
        if let WorkerError::OUTCOME_UNKNOWN(stop) = &mut error {
            stop.recovery = Some(Box::new(PendingWorker { child, group }));
        }
        error
    }

    fn read_pipe(
        input: &mut impl Read,
        output: &mut Vec<u8>,
        total_bytes: &mut usize,
        maximum_bytes: usize,
        should_retain: bool,
    ) -> Result<bool, WorkerStopReason> {
        let mut buffer = Zeroizing::new([0; 4096]);
        match input.read(&mut buffer[..]) {
            Ok(0) => Ok(true),
            Ok(count) => {
                *total_bytes = total_bytes
                    .checked_add(count)
                    .ok_or(WorkerStopReason::OUTPUT_LIMIT)?;
                if *total_bytes > maximum_bytes {
                    return Err(WorkerStopReason::OUTPUT_LIMIT);
                }
                if should_retain {
                    output.extend_from_slice(&buffer[..count]);
                }
                Ok(false)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(_) => Err(WorkerStopReason::PIPE_FAILURE),
        }
    }

    fn write_input(
        input: &mut Option<ChildStdin>,
        bytes: &[u8],
        position: &mut usize,
    ) -> Result<(), WorkerStopReason> {
        if let Some(pipe) = input
            && *position < bytes.len()
        {
            match pipe.write(&bytes[*position..]) {
                Ok(0) => return Err(WorkerStopReason::PIPE_FAILURE),
                Ok(count) => *position += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(WorkerStopReason::PIPE_FAILURE),
            }
        }
        if *position == bytes.len() {
            input.take();
        }
        Ok(())
    }

    fn validate_limits(
        executable: &Path,
        input: &[u8],
        limits: WorkerLimits,
    ) -> Result<(), WorkerError> {
        if !executable.is_absolute()
            || input.len() > MAX_INPUT_BYTES
            || !(MIN_WORKER_MEMORY_BYTES..=MAX_WORKER_MEMORY_BYTES)
                .contains(&limits.memory_max_bytes)
            || limits.memory_high_bytes == 0
            || limits.memory_high_bytes > limits.memory_max_bytes
            || !(1..=64).contains(&limits.max_tasks)
            || !(8..=64).contains(&limits.max_open_files)
            || limits.max_runtime.is_zero()
            || limits.max_runtime > Duration::from_secs(900)
            || limits.max_output_bytes == 0
            || limits.max_output_bytes > MAX_OUTPUT_BYTES
        {
            return Err(WorkerError::INVALID);
        }
        Ok(())
    }

    pub fn execute_worker(
        executable: &Path,
        input: &[u8],
        read_paths: &[PathBuf],
        write_paths: &[PathBuf],
        limits: WorkerLimits,
        guard: &StageGuard,
    ) -> Result<WorkerOutput, WorkerError> {
        execute_worker_recorded(
            executable,
            input,
            read_paths,
            write_paths,
            limits,
            guard,
            |_| Ok(()),
        )
    }

    pub fn execute_worker_recorded<F>(
        executable: &Path,
        input: &[u8],
        read_paths: &[PathBuf],
        write_paths: &[PathBuf],
        limits: WorkerLimits,
        guard: &StageGuard,
        before_launch: F,
    ) -> Result<WorkerOutput, WorkerError>
    where
        F: FnOnce(&WorkerIdentity) -> Result<(), WorkerError>,
    {
        validate_limits(executable, input, limits)?;
        guard.check().map_err(|error| {
            if error == ResourceError::DEADLINE_EXCEEDED {
                WorkerError::DEADLINE
            } else {
                WorkerError::CANCELED
            }
        })?;
        let group = WorkerGroup::create(limits)?;
        let identity = get_group_identity(&group.path)?;
        before_launch(&identity)?;
        guard.check().map_err(|error| {
            if error == ResourceError::DEADLINE_EXCEEDED {
                WorkerError::DEADLINE
            } else {
                WorkerError::CANCELED
            }
        })?;
        let mut child = spawn_worker(executable, &group, limits, read_paths, write_paths)?;
        let started = Instant::now();
        let Some(stdin) = child.stdin.take() else {
            return Err(stop_worker(child, group, WorkerStopReason::PIPE_FAILURE));
        };
        let Some(mut stdout) = child.stdout.take() else {
            return Err(stop_worker(child, group, WorkerStopReason::PIPE_FAILURE));
        };
        let Some(mut stderr) = child.stderr.take() else {
            return Err(stop_worker(child, group, WorkerStopReason::PIPE_FAILURE));
        };
        if [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()]
            .into_iter()
            .any(|fd| set_nonblocking(fd).is_err())
        {
            return Err(stop_worker(child, group, WorkerStopReason::PIPE_FAILURE));
        }
        let mut stdin = Some(stdin);
        let mut input_position = 0;
        let mut output = Vec::new();
        let mut discarded = Vec::new();
        let mut stdout_bytes = 0;
        let mut stderr_bytes = 0;
        let mut is_stdout_closed = false;
        let mut is_stderr_closed = false;
        loop {
            if let Err(error) = guard.check() {
                let reason = if error == ResourceError::DEADLINE_EXCEEDED {
                    WorkerStopReason::DEADLINE
                } else {
                    WorkerStopReason::CANCELED
                };
                return Err(stop_worker(child, group, reason));
            }
            if started.elapsed() >= limits.max_runtime {
                return Err(stop_worker(child, group, WorkerStopReason::DEADLINE));
            }
            if let Err(reason) = write_input(&mut stdin, input, &mut input_position) {
                return Err(stop_worker(child, group, reason));
            }
            if !is_stdout_closed {
                match read_pipe(
                    &mut stdout,
                    &mut output,
                    &mut stdout_bytes,
                    limits.max_output_bytes,
                    true,
                ) {
                    Ok(value) => is_stdout_closed = value,
                    Err(reason) => return Err(stop_worker(child, group, reason)),
                }
            }
            if !is_stderr_closed {
                match read_pipe(
                    &mut stderr,
                    &mut discarded,
                    &mut stderr_bytes,
                    limits.max_output_bytes,
                    false,
                ) {
                    Ok(value) => is_stderr_closed = value,
                    Err(reason) => return Err(stop_worker(child, group, reason)),
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return Err(stop_worker(child, group, WorkerStopReason::PROCESS_FAILURE));
                    }
                    if !matches!(group.is_populated(), Ok(false)) {
                        return Err(stop_worker(child, group, WorkerStopReason::PROCESS_FAILURE));
                    }
                    if is_stdout_closed && is_stderr_closed && stdin.is_none() {
                        let (Ok(peak), Ok(events)) =
                            (group.get_peak_bytes(), group.get_memory_events())
                        else {
                            return Err(group.get_stop(WorkerStopReason::EVIDENCE_FAILURE));
                        };
                        if events > 0 || peak > limits.memory_max_bytes {
                            return Err(group.get_stop(WorkerStopReason::MEMORY_LIMIT));
                        }
                        return Ok(WorkerOutput {
                            stdout: output,
                            memory_peak_bytes: peak,
                            memory_limit_events: events,
                        });
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    return Err(stop_worker(child, group, WorkerStopReason::PROCESS_FAILURE));
                }
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
    #[cfg(test)]
    mod tests {
        use super::{parse_event_counter, prove_removed_original, validate_worker_path};

        #[test]
        fn removed_original_proof_rejects_a_replacement_path() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("scope");
            std::fs::create_dir(&path).unwrap();
            let parent = std::fs::File::open(directory.path()).unwrap();
            let original = std::fs::File::open(&path).unwrap();
            assert!(!prove_removed_original(&parent, c"scope", &original, None).unwrap());
            std::fs::remove_dir(&path).unwrap();
            assert!(prove_removed_original(&parent, c"scope", &original, None).unwrap());
            std::fs::create_dir(&path).unwrap();
            assert!(prove_removed_original(&parent, c"scope", &original, None).is_err());
        }

        #[test]
        fn accepts_only_canonical_worker_group_paths() {
            let name = format!("worker_{}", "a".repeat(32));
            assert!(validate_worker_path(&format!("/scope/{name}"), "/scope").is_ok());
            for group in [
                format!("/scope/./{name}"),
                format!("/scope//{name}"),
                format!("/scope/{name}/x"),
                "/scope/worker_bad".into(),
                format!("/scope/worker_{}", "A".repeat(32)),
            ] {
                assert!(validate_worker_path(&group, "/scope").is_err());
            }
            assert!(validate_worker_path(&format!("/scope/{name}"), "/other").is_err());
        }

        #[test]
        fn rejects_missing_malformed_and_duplicate_kernel_evidence() {
            assert_eq!(
                parse_event_counter("populated 0\nfrozen 0\n", "populated").unwrap(),
                0
            );
            assert_eq!(
                parse_event_counter("oom 1\noom_kill 2\n", "oom_kill").unwrap(),
                2
            );
            for text in [
                "",
                "other 0",
                "oom_kill nope",
                "oom_kill 0\noom_kill 1",
                "oom_kill 18446744073709551616",
            ] {
                assert!(parse_event_counter(text, "oom_kill").is_err());
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{
    PendingWorker, execute_worker, execute_worker_recorded, get_current_worker_identity,
    prepare_worker_process, quiesce_recorded_worker, verify_current_worker_identity,
    verify_worker_envelope,
};

#[cfg(not(target_os = "linux"))]
pub fn verify_worker_envelope(_memory_max_bytes: u64) -> Result<(), WorkerError> {
    Err(WorkerError::UNSUPPORTED)
}

#[cfg(not(target_os = "linux"))]
pub fn execute_worker(
    _executable: &Path,
    _input: &[u8],
    _read_paths: &[PathBuf],
    _write_paths: &[PathBuf],
    _limits: WorkerLimits,
    _guard: &StageGuard,
) -> Result<WorkerOutput, WorkerError> {
    Err(WorkerError::UNSUPPORTED)
}

#[cfg(not(target_os = "linux"))]
pub fn prepare_worker_process() -> Result<(), WorkerError> {
    Err(WorkerError::UNSUPPORTED)
}

#[cfg(not(target_os = "linux"))]
pub fn execute_worker_recorded<F>(
    _executable: &Path,
    _input: &[u8],
    _read_paths: &[PathBuf],
    _write_paths: &[PathBuf],
    _limits: WorkerLimits,
    _guard: &StageGuard,
    _before_launch: F,
) -> Result<WorkerOutput, WorkerError>
where
    F: FnOnce(&crate::worker_identity::WorkerIdentity) -> Result<(), WorkerError>,
{
    Err(WorkerError::UNSUPPORTED)
}

#[cfg(not(target_os = "linux"))]
pub fn get_current_worker_identity() -> Result<crate::worker_identity::WorkerIdentity, WorkerError>
{
    Err(WorkerError::UNSUPPORTED)
}

#[cfg(not(target_os = "linux"))]
pub fn verify_current_worker_identity(
    _identity: &crate::worker_identity::WorkerIdentity,
) -> Result<(), WorkerError> {
    Err(WorkerError::UNSUPPORTED)
}

#[cfg(not(target_os = "linux"))]
pub fn quiesce_recorded_worker(
    _identity: &crate::worker_identity::WorkerIdentity,
    _guard: &StageGuard,
) -> Result<bool, WorkerError> {
    Err(WorkerError::UNSUPPORTED)
}
