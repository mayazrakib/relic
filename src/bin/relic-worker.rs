#[cfg(all(feature = "embedded-archive", unix))]
use relic::archive_worker::{execute_archive, read_request, write_report};

#[cfg(all(feature = "embedded-archive", unix))]
fn main() {
    let result = (|| {
        relic::worker_runtime::prepare_worker_process()
            .map_err(|_| relic::archive_worker::WorkerProtocolError::ENVELOPE)?;
        let request = read_request(std::io::stdin().lock())?;
        let report = execute_archive(&request)?;
        write_report(std::io::stdout().lock(), &report)
    })();

    if let Err(error) = result {
        use relic::archive_worker::WorkerProtocolError;
        let code = match error {
            WorkerProtocolError::INVALID => 2,
            WorkerProtocolError::ENVELOPE => 3,
            WorkerProtocolError::IO => 4,
            WorkerProtocolError::STATE => 5,
            WorkerProtocolError::RESOURCE => 6,
            WorkerProtocolError::ENGINE => 7,
            WorkerProtocolError::VERIFICATION => 8,
        };
        eprintln!("Archive worker failed.");
        std::process::exit(code);
    }
}

#[cfg(not(all(feature = "embedded-archive", unix)))]
fn main() {
    eprintln!("Archive worker is unavailable for this build.");
    std::process::exit(2);
}
