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

    if result.is_err() {
        eprintln!("Relic could not start or continue its local management service.");
        std::process::exit(4);
    }
}
