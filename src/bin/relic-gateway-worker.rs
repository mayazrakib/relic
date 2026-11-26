#[cfg(all(feature = "embedded-archive", target_os = "linux"))]
fn main() {
    use relic::gateway_worker::{GatewayWorkerError, execute_gateway, read_request, write_report};
    let result = (|| {
        relic::worker_runtime::prepare_worker_process()
            .map_err(|_| GatewayWorkerError::ENVELOPE)?;
        let request = read_request(std::io::stdin().lock())?;
        let report = execute_gateway(&request)?;
        write_report(std::io::stdout().lock(), &report)
    })();
    if let Err(error) = result {
        let code = match error {
            GatewayWorkerError::INVALID => 2,
            GatewayWorkerError::ENVELOPE => 3,
            GatewayWorkerError::IO => 4,
            GatewayWorkerError::STATE => 5,
            GatewayWorkerError::RESOURCE => 6,
            GatewayWorkerError::ENGINE => 7,
            GatewayWorkerError::VERIFICATION => 8,
            GatewayWorkerError::UNSUPPORTED => 9,
        };
        eprintln!("Gateway worker failed.");
        std::process::exit(code);
    }
}

#[cfg(not(all(feature = "embedded-archive", target_os = "linux")))]
fn main() {
    eprintln!("Gateway worker is unavailable for this build.");
    std::process::exit(2);
}
