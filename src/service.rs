#[cfg(not(unix))]
use std::future::Future;
#[cfg(not(unix))]
use std::io;
#[cfg(not(unix))]
use std::path::Path;

#[cfg(not(unix))]
use serde_json::Value;

#[cfg(unix)]
mod unix {
    use std::collections::HashMap;
    use std::fs::{self, File, OpenOptions};
    use std::future::Future;
    use std::io;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::Semaphore;
    use tokio::time::timeout;

    use crate::config::{normalize_job, parse_json_bytes};
    use crate::contracts;
    use crate::state::{StateError, StateStore};

    const MAX_FRAME: usize = 1_048_576;
    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const CURSOR_LIFETIME: Duration = Duration::from_secs(900);
    const MAX_CURSORS: usize = 1024;
    const SOCKET_NAME: &str = "relic.sock";

    struct Cursor {
        after: String,
        expires: Instant,
        owner: u32,
    }

    struct Context {
        directory: PathBuf,
        node_id: String,
        owner: u32,
        cursors: Mutex<HashMap<String, Cursor>>,
    }

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    async fn read_frame(stream: &mut UnixStream) -> io::Result<Value> {
        timeout(IO_TIMEOUT, async {
            let length = stream.read_u32().await? as usize;
            if length == 0 || length > MAX_FRAME {
                return Err(invalid("invalid frame length"));
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await?;
            parse_json_bytes(&bytes).map_err(|_| invalid("invalid JSON frame"))
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "frame read timed out"))?
    }

    async fn write_frame(stream: &mut UnixStream, value: &Value) -> io::Result<()> {
        let bytes = serde_json::to_vec(value).map_err(|_| invalid("invalid response"))?;
        if bytes.len() > MAX_FRAME {
            return Err(invalid("response exceeds frame limit"));
        }
        timeout(IO_TIMEOUT, async {
            stream.write_u32(bytes.len() as u32).await?;
            stream.write_all(&bytes).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "frame write timed out"))?
    }

    fn get_nonce() -> String {
        uuid::Uuid::now_v7().to_string()
    }

    fn validate_nonce(value: &Value) -> bool {
        value
            .as_str()
            .and_then(|text| uuid::Uuid::parse_str(text).ok())
            .is_some()
    }

    async fn establish_server(stream: &mut UnixStream, owner: u32) -> io::Result<()> {
        if stream.peer_cred()?.uid() != owner {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unauthorized peer",
            ));
        }
        let hello = read_frame(stream).await?;
        if hello.as_object().map(|value| value.len()) != Some(2)
            || hello["protocol"] != 1
            || !validate_nonce(&hello["client_nonce"])
        {
            return Err(invalid("invalid session hello"));
        }
        let daemon_nonce = get_nonce();
        let challenge = json!({"protocol": 1, "client_nonce": hello["client_nonce"], "daemon_nonce": daemon_nonce});
        write_frame(stream, &challenge).await?;
        let response = read_frame(stream).await?;
        if response != challenge {
            return Err(invalid("invalid session challenge"));
        }
        write_frame(stream, &json!({"protocol": 1, "accepted": true})).await
    }

    async fn establish_client(stream: &mut UnixStream, owner: u32) -> io::Result<()> {
        if stream.peer_cred()?.uid() != owner {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unauthorized daemon",
            ));
        }
        let client_nonce = get_nonce();
        write_frame(
            stream,
            &json!({"protocol": 1, "client_nonce": client_nonce}),
        )
        .await?;
        let challenge = read_frame(stream).await?;
        if challenge.as_object().map(|value| value.len()) != Some(3)
            || challenge["protocol"] != 1
            || challenge["client_nonce"] != client_nonce
            || !validate_nonce(&challenge["daemon_nonce"])
        {
            return Err(invalid("invalid daemon challenge"));
        }
        write_frame(stream, &challenge).await?;
        if read_frame(stream).await? != json!({"protocol": 1, "accepted": true}) {
            return Err(invalid("session rejected"));
        }
        Ok(())
    }

    fn error(id: Value, correlation: Option<&str>, code: &str, message: &str) -> Value {
        let mut result =
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32001, "message": message}});
        if let Some(correlation) = correlation {
            result["error"]["data"] = json!({"code": code, "retryable": false, "phase": "validation", "correlation_id": correlation});
        }
        result
    }

    fn success(id: Value, result: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "result": result})
    }

    fn dispatch(context: &Context, request: Value) -> Value {
        if contracts::validate_request(&request).is_err() {
            return json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request."}});
        }
        let id = request["id"].clone();
        let params = &request["params"];
        let correlation = params["correlation_id"].as_str().unwrap();
        let failure = |code, message| error(id.clone(), Some(correlation), code, message);
        let method = request["method"].as_str().unwrap();
        if method == "get_status" {
            return success(
                id,
                json!({"schema_version": 1, "node_id": context.node_id, "ready": false, "quorum": "not_applicable", "correlation_id": correlation, "protection": {"state": "unconfigured", "unknown_count": "0", "breached_count": "0", "at_risk_count": "0", "unprotected_count": "0"}}),
            );
        }
        if method == "validate_job" {
            let is_valid = normalize_job(&params["job"]).is_ok();
            let errors = if is_valid {
                json!([])
            } else {
                json!([{"path": "", "code": "INVALID_CONFIGURATION"}])
            };
            return success(
                id,
                json!({"schema_version": 1, "valid": is_valid, "errors": errors, "correlation_id": correlation}),
            );
        }
        if !["create_job", "update_job", "get_job", "list_jobs"].contains(&method) {
            return failure("UNSUPPORTED_CAPABILITY", "Operation is unavailable.");
        }
        let mut store = match StateStore::open(&context.directory) {
            Ok(store) => store,
            Err(_) => return failure("INTERNAL", "State is unavailable."),
        };
        match method {
            "create_job" | "update_job" => {
                let job = match normalize_job(&params["job"]) {
                    Ok(job) => job,
                    Err(_) => {
                        return failure("INVALID_CONFIGURATION", "Job configuration is invalid.");
                    }
                };
                if job["enabled"] != false {
                    return failure("UNSUPPORTED_CAPABILITY", "Enabled jobs are unavailable.");
                }
                let result = if method == "create_job" {
                    store.put_job_idempotent(
                        &job,
                        None,
                        params["idempotency_key"].as_str().unwrap(),
                    )
                } else {
                    store.put_job(
                        &job,
                        params["expected_revision"]
                            .as_u64()
                            .map(|value| value as u32),
                    )
                };
                match result {
                    Ok(record) => success(
                        id,
                        json!({"schema_version": 1, "job_id": record.job_id, "revision": record.revision, "correlation_id": correlation}),
                    ),
                    Err(StateError::RevisionConflict) => {
                        failure("REVISION_CONFLICT", "Job revision conflicts.")
                    }
                    Err(StateError::IdempotencyConflict) => {
                        failure("IDEMPOTENCY_CONFLICT", "Idempotency key conflicts.")
                    }
                    Err(_) => failure("INTERNAL", "State is unavailable."),
                }
            }
            "get_job" => match store.get_job(params["job_id"].as_str().unwrap()) {
                Ok(Some(record)) => success(
                    id,
                    json!({"schema_version": 1, "job": record.definition, "correlation_id": correlation}),
                ),
                Ok(None) => failure("NOT_FOUND", "Job was not found."),
                Err(_) => failure("INTERNAL", "State is unavailable."),
            },
            "list_jobs" => list_jobs(context, &store, &id, correlation, params),
            _ => failure("UNSUPPORTED_CAPABILITY", "Operation is unavailable."),
        }
    }

    fn list_jobs(
        context: &Context,
        store: &StateStore,
        id: &Value,
        correlation: &str,
        params: &Value,
    ) -> Value {
        let mut cursors = context.cursors.lock().unwrap();
        cursors.retain(|_, cursor| cursor.expires > Instant::now());
        let after = if let Some(token) = params["cursor"].as_str() {
            match cursors.get(token) {
                Some(cursor) if cursor.owner == context.owner => cursor.after.clone(),
                _ => {
                    return error(
                        id.clone(),
                        Some(correlation),
                        "INVALID_CURSOR",
                        "Cursor is invalid or expired.",
                    );
                }
            }
        } else {
            String::new()
        };
        let page_size = params["page_size"].as_u64().unwrap_or(100) as u32;
        let mut items = Vec::new();
        let mut last_id = after;
        let mut more = false;
        let mut encoded_bytes = 1024usize;

        for _ in 0..page_size {
            let mut jobs = match store.list_jobs(&last_id, 1) {
                Ok(jobs) => jobs,
                Err(_) => {
                    return error(
                        id.clone(),
                        Some(correlation),
                        "INTERNAL",
                        "State is unavailable.",
                    );
                }
            };
            let Some(job) = jobs.pop() else {
                break;
            };
            let item = json!({"kind": "job", "id": job.job_id, "name": job.definition["name"]});
            let length = serde_json::to_vec(&item)
                .map(|value| value.len() + 1)
                .unwrap_or(MAX_FRAME);
            if encoded_bytes.saturating_add(length) > MAX_FRAME {
                if items.is_empty() {
                    return error(
                        id.clone(),
                        Some(correlation),
                        "RESOURCE_EXHAUSTED",
                        "Job detail exceeds frame capacity.",
                    );
                }
                more = true;
                break;
            }
            encoded_bytes += length;
            last_id = job.job_id;
            items.push(item);
        }

        if !more && items.len() == page_size as usize {
            more = match store.list_jobs(&last_id, 1) {
                Ok(jobs) => !jobs.is_empty(),
                Err(_) => {
                    return error(
                        id.clone(),
                        Some(correlation),
                        "INTERNAL",
                        "State is unavailable.",
                    );
                }
            };
        }
        let next_cursor = if more {
            if cursors.len() >= MAX_CURSORS {
                return error(
                    id.clone(),
                    Some(correlation),
                    "RESOURCE_EXHAUSTED",
                    "Cursor capacity is exhausted.",
                );
            }
            let token = get_nonce();
            cursors.insert(
                token.clone(),
                Cursor {
                    after: last_id,
                    expires: Instant::now() + CURSOR_LIFETIME,
                    owner: context.owner,
                },
            );
            Some(token)
        } else {
            None
        };
        success(
            id.clone(),
            json!({"schema_version": 1, "items": items, "next_cursor": next_cursor, "correlation_id": correlation}),
        )
    }

    async fn handle(mut stream: UnixStream, context: Arc<Context>) -> io::Result<()> {
        establish_server(&mut stream, context.owner).await?;
        let request = read_frame(&mut stream).await?;
        let response = tokio::task::spawn_blocking(move || dispatch(&context, request))
            .await
            .map_err(|_| io::Error::other("request worker failed"))?;
        write_frame(&mut stream, &response).await
    }

    pub async fn serve<F>(directory: &Path, shutdown: F) -> io::Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        let mut store =
            StateStore::open(directory).map_err(|_| io::Error::other("state unavailable"))?;
        let owner = fs::metadata(directory)?.uid();
        let node_id = store
            .get_node_id()
            .map_err(|_| io::Error::other("state unavailable"))?;
        drop(store);
        let lock_path = directory.join("daemon.lock");
        if fs::symlink_metadata(&lock_path)
            .is_ok_and(|value| !value.is_file() || value.file_type().is_symlink())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid lock file",
            ));
        }
        let lock: File = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.try_lock()
            .map_err(|_| io::Error::new(io::ErrorKind::AddrInUse, "daemon already running"))?;
        let socket_path = directory.join(SOCKET_NAME);
        if let Ok(metadata) = fs::symlink_metadata(&socket_path) {
            if !metadata.file_type().is_socket() || metadata.uid() != owner {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "invalid existing socket",
                ));
            }
            fs::remove_file(&socket_path)?;
        }
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let context = Arc::new(Context {
            directory: directory.to_owned(),
            node_id,
            owner,
            cursors: Mutex::new(HashMap::new()),
        });
        let sessions = Arc::new(Semaphore::new(32));
        let mut workers = tokio::task::JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                _ = workers.join_next(), if !workers.is_empty() => {},
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    if let Ok(permit) = sessions.clone().try_acquire_owned() {
                        let context = context.clone();
                        workers.spawn(async move { let _permit = permit; let _ = handle(stream, context).await; });
                    }
                }
            }
        }
        drop(listener);
        while workers.join_next().await.is_some() {}
        fs::remove_file(socket_path)?;
        drop(lock);
        Ok(())
    }

    pub async fn request(directory: &Path, request: Value) -> io::Result<Value> {
        let socket_path = directory.join(SOCKET_NAME);
        let metadata = fs::symlink_metadata(&socket_path)?;
        let directory_metadata = fs::symlink_metadata(directory)?;
        if !directory_metadata.is_dir()
            || directory_metadata.file_type().is_symlink()
            || directory_metadata.permissions().mode() & 0o077 != 0
            || !metadata.file_type().is_socket()
            || metadata.uid() != directory_metadata.uid()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "insecure daemon endpoint",
            ));
        }
        let mut stream = timeout(IO_TIMEOUT, UnixStream::connect(socket_path))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection timed out"))??;
        establish_client(&mut stream, metadata.uid()).await?;
        write_frame(&mut stream, &request).await?;
        read_frame(&mut stream).await
    }
}

#[cfg(unix)]
pub use unix::{request, serve};

#[cfg(not(unix))]
pub async fn serve<F>(_directory: &Path, _shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native local IPC is unavailable on this platform",
    ))
}

#[cfg(not(unix))]
pub async fn request(_directory: &Path, _request: Value) -> io::Result<Value> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native local IPC is unavailable on this platform",
    ))
}
