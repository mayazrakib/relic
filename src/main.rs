use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(
    name = "relic",
    version,
    about = "Manage Relic and validate backup definitions"
)]
struct Arguments {
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Operation,
}

#[derive(Subcommand)]
enum Operation {
    Status,
    Doctor,
    Job {
        #[command(subcommand)]
        command: JobOperation,
    },
}

#[derive(Subcommand)]
enum JobOperation {
    Validate {
        path: PathBuf,
    },
    Apply {
        path: PathBuf,
        #[arg(long)]
        expected_revision: Option<u32>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    List {
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 100)]
        page_size: u32,
    },
    Get {
        job_id: String,
    },
}

fn default_state_directory() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        return Some(PathBuf::from(path).join("relic"));
    }

    #[cfg(windows)]
    if let Some(path) = std::env::var_os("LOCALAPPDATA") {
        return Some(PathBuf::from(path).join("relic"));
    }

    std::env::var_os("HOME").map(|path| PathBuf::from(path).join(".local/state/relic"))
}

fn make_request(method: &str, mut params: Value) -> Value {
    let request_id = uuid::Uuid::now_v7().to_string();
    params["correlation_id"] = json!(request_id);

    json!({"jsonrpc":"2.0","id":request_id,"method":method,"params":params})
}

async fn execute(arguments: Arguments) -> Result<Value, (&'static str, i32)> {
    if let Operation::Job {
        command: JobOperation::Validate { path },
    } = &arguments.command
    {
        let definition = relic::config::load_job(path).map_err(|_| ("INVALID_INPUT", 2))?;

        return Ok(
            json!({"schema_version":1,"valid":true,"job_id":definition["job_id"],"enabled":definition["enabled"],"execution_preflight_complete":false}),
        );
    }

    let directory = arguments
        .state_dir
        .or_else(default_state_directory)
        .ok_or(("STATE_DIRECTORY_REQUIRED", 2))?;
    let request = match arguments.command {
        Operation::Status => make_request("get_status", json!({})),
        Operation::Doctor => {
            let database = directory.join("state.sqlite3");

            if !database.exists() {
                return Ok(
                    json!({"schema_version":1,"state_exists":false,"daemon_ready":false,"native_platform":std::env::consts::OS}),
                );
            }

            let store =
                relic::state::StateStore::open(&directory).map_err(|_| ("STATE_UNAVAILABLE", 4))?;
            let integrity = store
                .check_integrity()
                .map_err(|_| ("STATE_UNAVAILABLE", 4))?;

            return Ok(
                json!({"schema_version":1,"state_exists":true,"database_integrity":integrity,"archive_execution_available":false,"cluster_available":false,"native_platform":std::env::consts::OS}),
            );
        }
        Operation::Job { command } => match command {
            JobOperation::Validate { .. } => unreachable!(),
            JobOperation::Get { job_id } => make_request("get_job", json!({"job_id":job_id})),
            JobOperation::List { cursor, page_size } => {
                let mut params = json!({"page_size":page_size});

                if let Some(cursor) = cursor {
                    params["cursor"] = json!(cursor);
                }

                make_request("list_jobs", params)
            }
            JobOperation::Apply {
                path,
                expected_revision,
                idempotency_key,
            } => {
                let job = relic::config::load_job(&path).map_err(|_| ("INVALID_INPUT", 2))?;

                if let Some(expected_revision) = expected_revision {
                    make_request(
                        "update_job",
                        json!({"expected_revision":expected_revision,"job":job}),
                    )
                } else {
                    make_request(
                        "create_job",
                        json!({"job":job,"idempotency_key":idempotency_key.unwrap_or_else(|| uuid::Uuid::now_v7().to_string())}),
                    )
                }
            }
        },
    };
    relic::service::request(&directory, request)
        .await
        .map_err(|_| ("DAEMON_UNAVAILABLE", 4))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arguments = Arguments::parse();

    match execute(arguments).await {
        Ok(value) => {
            println!("{}", value);

            if value.get("error").is_some() {
                std::process::exit(1);
            }
        }
        Err((code, exit_code)) => {
            eprintln!("{}", json!({"schema_version":1,"error":{"code":code}}));
            std::process::exit(exit_code);
        }
    }
}
