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
    use std::os::unix::process::CommandExt;
    use std::path::{Component, Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use zeroize::Zeroizing;

    use super::{WorkerError, WorkerLimits, WorkerOutput, WorkerStop, WorkerStopReason};
    use crate::resources::{ResourceError, StageGuard};
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
            let group = Self { path };
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
            let text = fs::read_to_string(self.path.join("cgroup.events"))
                .map_err(|_| WorkerError::UNSUPPORTED)?;
            match parse_event_counter(&text, "populated")? {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(WorkerError::UNSUPPORTED),
            }
        }

        fn kill(&self) {
            let _ = fs::write(self.path.join("cgroup.kill"), "1");
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
                let _ = fs::remove_dir(&self.path);
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

    fn stop_worker(
        child: &mut Child,
        group: &WorkerGroup,
        reason: WorkerStopReason,
    ) -> WorkerError {
        group.kill();
        let deadline = Instant::now() + REAP_TIMEOUT;
        while Instant::now() < deadline {
            let is_reaped = child.try_wait().ok().flatten().is_some();
            if is_reaped && matches!(group.is_populated(), Ok(false)) {
                let reason = if group.get_memory_events().is_ok_and(|count| count > 0) {
                    WorkerStopReason::MEMORY_LIMIT
                } else {
                    reason
                };
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
        group.get_stop(WorkerStopReason::UNREAPED)
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
        validate_limits(executable, input, limits)?;
        guard.check().map_err(|error| {
            if error == ResourceError::DEADLINE_EXCEEDED {
                WorkerError::DEADLINE
            } else {
                WorkerError::CANCELED
            }
        })?;
        let group = WorkerGroup::create(limits)?;
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
            return Err(stop_worker(
                &mut child,
                &group,
                WorkerStopReason::PIPE_FAILURE,
            ));
        };
        let Some(mut stdout) = child.stdout.take() else {
            return Err(stop_worker(
                &mut child,
                &group,
                WorkerStopReason::PIPE_FAILURE,
            ));
        };
        let Some(mut stderr) = child.stderr.take() else {
            return Err(stop_worker(
                &mut child,
                &group,
                WorkerStopReason::PIPE_FAILURE,
            ));
        };
        if [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()]
            .into_iter()
            .any(|fd| set_nonblocking(fd).is_err())
        {
            return Err(stop_worker(
                &mut child,
                &group,
                WorkerStopReason::PIPE_FAILURE,
            ));
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
                return Err(stop_worker(&mut child, &group, reason));
            }
            if started.elapsed() >= limits.max_runtime {
                return Err(stop_worker(&mut child, &group, WorkerStopReason::DEADLINE));
            }
            if let Err(reason) = write_input(&mut stdin, input, &mut input_position) {
                return Err(stop_worker(&mut child, &group, reason));
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
                    Err(reason) => return Err(stop_worker(&mut child, &group, reason)),
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
                    Err(reason) => return Err(stop_worker(&mut child, &group, reason)),
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return Err(stop_worker(
                            &mut child,
                            &group,
                            WorkerStopReason::PROCESS_FAILURE,
                        ));
                    }
                    if !matches!(group.is_populated(), Ok(false)) {
                        return Err(stop_worker(
                            &mut child,
                            &group,
                            WorkerStopReason::PROCESS_FAILURE,
                        ));
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
                    return Err(stop_worker(
                        &mut child,
                        &group,
                        WorkerStopReason::PROCESS_FAILURE,
                    ));
                }
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
    #[cfg(test)]
    mod tests {
        use super::parse_event_counter;

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
pub use linux::{execute_worker, prepare_worker_process, verify_worker_envelope};

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
