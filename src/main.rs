use clap::Parser;
use portmap::cli::Args;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = portmap::scan::run_scan(&args).await {
        eprintln!("pmap: {e}");
        std::process::exit(1);
    }
}
