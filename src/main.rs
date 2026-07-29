use clap::Parser;
use pmap::cli::Args;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = pmap::scan::run_scan(&args).await {
        eprintln!("pmap: {e}");
        std::process::exit(1);
    }
}
