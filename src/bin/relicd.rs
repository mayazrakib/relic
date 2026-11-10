use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "relicd",
    version,
    about = "Run the Relic local management daemon"
)]
struct Arguments {
    #[arg(long)]
    state_dir: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arguments = Arguments::parse();
    let result = relic::service::serve(&arguments.state_dir, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await;

    if let Err(error) = result {
        eprintln!(
            "Relic local management service failed ({:?}).",
            error.kind()
        );
        std::process::exit(4);
    }
}
