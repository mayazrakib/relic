#![cfg(unix)]

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::Value;

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn command_line_validates_and_applies_disabled_jobs_through_real_daemon() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    let policy: Value =
        serde_json::from_str(include_str!("../fixtures/contracts/policy.json")).unwrap();
    let definition = directory.path().join("job.json");
    std::fs::write(&definition, serde_json::to_vec(&policy["job"]).unwrap()).unwrap();
    let validated = Command::new(env!("CARGO_BIN_EXE_relic"))
        .args(["job", "validate"])
        .arg(&definition)
        .output()
        .unwrap();
    assert!(validated.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&validated.stdout).unwrap()["execution_preflight_complete"],
        false
    );
    let daemon = Command::new(env!("CARGO_BIN_EXE_relicd"))
        .arg("--state-dir")
        .arg(&state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut daemon = Daemon(daemon);

    for _ in 0..100 {
        if state.join("relic.sock").exists() {
            break;
        }

        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "daemon exited before readiness"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(state.join("relic.sock").exists());
    let status = Command::new(env!("CARGO_BIN_EXE_relic"))
        .arg("--state-dir")
        .arg(&state)
        .arg("status")
        .output()
        .unwrap();
    assert!(status.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&status.stdout).unwrap()["result"]["ready"],
        false
    );
    let applied = Command::new(env!("CARGO_BIN_EXE_relic"))
        .arg("--state-dir")
        .arg(&state)
        .args(["job", "apply"])
        .arg(&definition)
        .args(["--idempotency-key", "cli_test_1"])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let listed = Command::new(env!("CARGO_BIN_EXE_relic"))
        .arg("--state-dir")
        .arg(&state)
        .args(["job", "list"])
        .output()
        .unwrap();
    assert!(listed.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&listed.stdout).unwrap()["result"]["items"][0]["id"],
        "job_1"
    );
}
