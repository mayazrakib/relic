#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use relic::resources::StageGuard;
use relic::worker_runtime::{
    WorkerError, WorkerLimits, WorkerStopReason, execute_worker, verify_worker_envelope,
};

fn get_limits() -> WorkerLimits {
    WorkerLimits {
        memory_max_bytes: 32 * 1024 * 1024,
        memory_high_bytes: 24 * 1024 * 1024,
        max_tasks: 16,
        max_open_files: 32,
        max_runtime: Duration::from_secs(5),
        max_output_bytes: 4096,
    }
}

fn create_script(root: &Path, code: &str) -> PathBuf {
    let path = root.join("worker.py");
    fs::write(&path, format!("#!/usr/bin/python3\n{code}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn rejects_invalid_limits_and_prelaunch_cancellation() {
    let guard = StageGuard::default();
    assert!(matches!(
        execute_worker(Path::new("relative"), b"", &[], &[], get_limits(), &guard),
        Err(WorkerError::INVALID)
    ));
    assert!(matches!(
        execute_worker(
            Path::new("/does/not/exist"),
            b"",
            &[],
            &[],
            WorkerLimits {
                memory_max_bytes: u64::MAX,
                ..get_limits()
            },
            &guard
        ),
        Err(WorkerError::INVALID)
    ));
    guard.cancellation.cancel();
    assert!(matches!(
        execute_worker(
            Path::new("/does/not/exist"),
            b"",
            &[],
            &[],
            get_limits(),
            &guard
        ),
        Err(WorkerError::CANCELED)
    ));
    assert!(verify_worker_envelope(get_limits().memory_max_bytes).is_err());
}

#[test]
#[ignore = "requires verified delegated Linux cgroup development guard"]
fn contains_child_below_the_verified_parent_and_closes_secret_input() {
    let directory = tempfile::tempdir().unwrap();
    let script = create_script(
        directory.path(),
        "from pathlib import Path\nimport sys\nmember=next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))\nroot=Path('/sys/fs/cgroup')/member.lstrip('/')\nassert root.name.startswith('worker_')\nassert (root/'memory.max').read_text().strip()=='33554432'\nassert (root/'memory.swap.max').read_text().strip()=='0'\nassert (root.parent/'memory.max').read_text().strip()=='1073741824'\nassert (root.parent/'memory.high').read_text().strip()=='805306368'\nassert sys.stdin.buffer.read()==b'bounded private input'\nimport resource\nassert resource.getrlimit(resource.RLIMIT_CORE)==(0,0)\nassert (root/'cpu.max').read_text().strip()=='100000 100000'\nstatus=Path('/proc/self/status').read_text()\nassert 'NoNewPrivs:\t1' in status\nassert all(int(line.split()[1],16)==0 for line in status.splitlines() if line.startswith(('CapEff:','CapPrm:','CapAmb:')))\nsys.stdout.buffer.write(b'verified')",
    );
    let output = execute_worker(
        &script,
        b"bounded private input",
        &[],
        &[],
        get_limits(),
        &StageGuard::default(),
    )
    .unwrap();
    assert_eq!(output.stdout, b"verified");
    assert!(
        output.memory_peak_bytes > 0 && output.memory_peak_bytes <= get_limits().memory_max_bytes
    );
    assert_eq!(output.memory_limit_events, 0);
}

#[test]
#[ignore = "requires verified delegated Linux cgroup development guard"]
fn kills_descendants_holding_pipes_without_waiting_for_eof() {
    let directory = tempfile::tempdir().unwrap();
    let script = create_script(
        directory.path(),
        "import os,time\nif os.fork()==0:\n    time.sleep(30)\nelse:\n    os._exit(0)",
    );
    let started = Instant::now();
    let result = execute_worker(&script, b"", &[], &[], get_limits(), &StageGuard::default());
    assert!(
        matches!(result, Err(WorkerError::OUTCOME_UNKNOWN(ref stop)) if stop.reason==WorkerStopReason::PROCESS_FAILURE)
    );
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[test]
#[ignore = "requires verified delegated Linux cgroup development guard"]
fn bounds_output_and_never_blocks_writing_to_an_unread_pipe() {
    let directory = tempfile::tempdir().unwrap();
    let script = create_script(
        directory.path(),
        "import sys\nwhile True:\n    sys.stdout.buffer.write(b'x'*4096)\n    sys.stdout.buffer.flush()",
    );
    assert!(
        matches!(execute_worker(&script, b"", &[], &[], get_limits(), &StageGuard::default()), Err(WorkerError::OUTCOME_UNKNOWN(ref stop)) if stop.reason==WorkerStopReason::OUTPUT_LIMIT)
    );
    let script = create_script(directory.path(), "import time\ntime.sleep(30)");
    let started = Instant::now();
    assert!(
        matches!(execute_worker(&script, &vec![0; 64*1024+4], &[], &[], WorkerLimits { max_runtime: Duration::from_millis(200), ..get_limits() }, &StageGuard::default()), Err(WorkerError::OUTCOME_UNKNOWN(ref stop)) if stop.reason==WorkerStopReason::DEADLINE)
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
#[ignore = "requires verified delegated Linux cgroup development guard"]
fn enforces_physical_memory_and_parent_driven_cancellation() {
    let directory = tempfile::tempdir().unwrap();
    let script = create_script(
        directory.path(),
        "buffers=[]\nwhile True:\n    buffers.append(bytearray(1024*1024))",
    );
    let limits = WorkerLimits {
        memory_max_bytes: 16 * 1024 * 1024,
        memory_high_bytes: 16 * 1024 * 1024,
        max_runtime: Duration::from_secs(5),
        ..get_limits()
    };
    let result = execute_worker(&script, b"", &[], &[], limits, &StageGuard::default());
    assert!(
        matches!(result, Err(WorkerError::OUTCOME_UNKNOWN(ref stop)) if stop.reason==WorkerStopReason::MEMORY_LIMIT && stop.memory_limit_events>0),
        "{}",
        match &result {
            Err(error) => format!("{error:?}"),
            Ok(_) => "unexpected success".into(),
        }
    );
    let script = create_script(directory.path(), "import time\ntime.sleep(30)");
    let guard = StageGuard::default();
    let token = guard.cancellation.clone();
    let canceler = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        token.cancel();
    });
    let started = Instant::now();
    assert!(
        matches!(execute_worker(&script, b"", &[], &[], get_limits(), &guard), Err(WorkerError::OUTCOME_UNKNOWN(ref stop)) if stop.reason==WorkerStopReason::CANCELED)
    );
    canceler.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
#[ignore = "requires delegated Linux cgroup guard with Landlock"]
fn denies_cgroup_escape_network_namespace_and_ungranted_file_access() {
    let directory = tempfile::tempdir().unwrap();
    let secret = directory.path().join("ungranted_secret");
    fs::write(&secret, b"must remain inaccessible").unwrap();
    let code = format!(
        "from pathlib import Path\nimport ctypes,os,socket\nlibc=ctypes.CDLL(None,use_errno=True)\nmember=next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))\nroot=Path('/sys/fs/cgroup')/member.lstrip('/')\nfor target,value in [(root.parent/'supervisor'/'cgroup.procs',str(os.getpid())),(root/'memory.max','max')]:\n    try:\n        target.write_text(value)\n        raise RuntimeError('cgroup escape permitted')\n    except PermissionError:\n        pass\nfor family in [socket.AF_UNIX,socket.AF_INET]:\n    try:\n        socket.socket(family,socket.SOCK_STREAM)\n        raise RuntimeError('socket permitted')\n    except PermissionError:\n        pass\nassert libc.syscall(272,0x10000000)==-1 and ctypes.get_errno()==1\ntry:\n    Path({:?}).read_bytes()\n    raise RuntimeError('ungranted read permitted')\nexcept PermissionError:\n    pass\ntry:\n    os.chmod(root/'cgroup.kill',0)\n    raise RuntimeError('cgroup metadata change permitted')\nexcept PermissionError:\n    pass\nprint('restrictions verified')",
        secret.to_str().unwrap()
    );
    let script = create_script(directory.path(), &code);
    let output =
        execute_worker(&script, b"", &[], &[], get_limits(), &StageGuard::default()).unwrap();
    assert_eq!(output.stdout, b"restrictions verified\n");
}

#[test]
#[ignore = "requires delegated Linux cgroup guard with Landlock"]
fn grants_repository_writes_while_preserving_readonly_sources() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let repository = directory.path().join("repository");
    for path in [&source, &repository] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(source.join("selected"), b"selected bytes").unwrap();
    let code = format!(
        "from pathlib import Path\nsource=Path({:?})\nrepository=Path({:?})\nassert (source/'selected').read_bytes()==b'selected bytes'\nfor path in [source/'selected',source/'unexpected']:\n    try:\n        path.write_text('forbidden')\n        raise RuntimeError('source write permitted')\n    except PermissionError:\n        pass\n(repository/'allowed').write_text('allowed')\nprint('roles verified')",
        source.to_str().unwrap(),
        repository.to_str().unwrap()
    );
    let script = create_script(directory.path(), &code);
    let output = execute_worker(
        &script,
        b"",
        std::slice::from_ref(&source),
        std::slice::from_ref(&repository),
        get_limits(),
        &StageGuard::default(),
    )
    .unwrap();
    assert_eq!(output.stdout, b"roles verified\n");
    assert_eq!(
        fs::read(source.join("selected")).unwrap(),
        b"selected bytes"
    );
    assert!(!source.join("unexpected").exists());
    assert_eq!(fs::read(repository.join("allowed")).unwrap(), b"allowed");
}

#[test]
#[ignore = "requires verified delegated Linux cgroup development guard"]
fn retains_recovery_handle_until_worker_termination_is_proved() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let marker = directory.path().join("membership");
    let code = format!(
        "from pathlib import Path\nimport time\nmember=next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))\nPath({:?}).write_text(member)\ntime.sleep(15)",
        marker.to_str().unwrap()
    );
    let script = create_script(directory.path(), &code);
    let observer = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok(member) = fs::read_to_string(&marker) {
                let control = Path::new("/sys/fs/cgroup")
                    .join(member.trim().trim_start_matches('/'))
                    .join("cgroup.kill");
                assert!(
                    control
                        .parent()
                        .unwrap()
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with("worker_")
                );
                fs::set_permissions(&control, fs::Permissions::from_mode(0o000)).unwrap();
                return control;
            }
            assert!(
                Instant::now() < deadline,
                "worker did not report its membership"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let result = execute_worker(
        &script,
        b"",
        &[],
        &[directory.path().to_path_buf()],
        WorkerLimits {
            max_runtime: Duration::from_secs(1),
            ..get_limits()
        },
        &StageGuard::default(),
    );
    let control = observer.join().unwrap();
    // Restore the kill control before any assertions, including a failing result assertion.
    fs::set_permissions(control, fs::Permissions::from_mode(0o600)).unwrap();
    let Err(WorkerError::OUTCOME_UNKNOWN(mut stop)) = result else {
        panic!("expected uncertain termination");
    };
    assert_eq!(stop.reason, WorkerStopReason::UNREAPED);
    let mut pending = stop
        .recovery
        .take()
        .expect("live worker ownership must be retained");
    assert!(!pending.has_ended());
    assert!(pending.try_reap());
    assert!(pending.has_ended());
}
