#![cfg(unix)]

use std::time::Duration;

use relic::service::{request, serve};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::time::sleep;

fn get_request(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": "request_1", "method": method, "params": params})
}

fn get_job() -> Value {
    json!({"schema_version": 1, "job_id": "job_1", "revision": 1, "name": "Example", "scope": "local", "method": "archive", "sources": [{"source_id": "source_1", "endpoint": "source"}], "destinations": [{"destination_id": "destination_1", "endpoint": "destination"}]})
}

#[tokio::test]
async fn serves_authenticated_requests_and_persists_disabled_jobs() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state");
    let daemon_path = path.clone();
    let (stop, stopped) = oneshot::channel();
    let daemon = tokio::spawn(async move {
        serve(&daemon_path, async {
            let _ = stopped.await;
        })
        .await
    });
    for _ in 0..100 {
        if path.join("relic.sock").exists() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert!(path.join("relic.sock").exists());
    let status = request(
        &path,
        get_request("get_status", json!({"correlation_id": "correlation_1"})),
    )
    .await
    .unwrap();
    assert_eq!(status["result"]["ready"], false);
    relic::contracts::validate_response(&status).unwrap();
    let job = get_job();
    let create = get_request(
        "create_job",
        json!({"correlation_id":"correlation_1", "idempotency_key":"key_1", "job":job}),
    );
    let first = request(&path, create.clone()).await.unwrap();
    assert_eq!(first["result"]["job_id"], "job_1");
    relic::contracts::validate_response(&first).unwrap();
    assert_eq!(request(&path, create).await.unwrap(), first);
    let loaded = request(
        &path,
        get_request(
            "get_job",
            json!({"correlation_id":"correlation_1", "job_id":"job_1"}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(loaded["result"]["job"]["enabled"], false);
    relic::contracts::validate_response(&loaded).unwrap();
    let listing = request(
        &path,
        get_request("list_jobs", json!({"correlation_id":"correlation_1"})),
    )
    .await
    .unwrap();
    assert_eq!(listing["result"]["items"][0]["id"], "job_1");
    relic::contracts::validate_response(&listing).unwrap();
    let mut enabled = get_job();
    enabled["enabled"] = json!(true);
    let rejected = request(
        &path,
        get_request(
            "create_job",
            json!({"correlation_id":"correlation_1", "idempotency_key":"key_2", "job":enabled}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(rejected["error"]["data"]["code"], "UNSUPPORTED_CAPABILITY");
    assert_eq!(rejected["error"]["code"], -32001);
    relic::contracts::validate_response(&rejected).unwrap();
    let invalid = request(&path, json!({"secret": "SECRET_TEST_VALUE"}))
        .await
        .unwrap();
    assert!(!invalid.to_string().contains("SECRET_TEST_VALUE"));
    assert_eq!(
        serve(&path, async {}).await.unwrap_err().kind(),
        std::io::ErrorKind::AddrInUse
    );
    let mut raw = UnixStream::connect(path.join("relic.sock")).await.unwrap();
    raw.write_u32(1_048_577).await.unwrap();
    drop(raw);
    let again = request(
        &path,
        get_request("get_status", json!({"correlation_id":"correlation_2"})),
    )
    .await
    .unwrap();
    assert_eq!(again["result"]["node_id"], status["result"]["node_id"]);
    stop.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    assert!(!path.join("relic.sock").exists());
}
