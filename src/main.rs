use clap::Parser;
use pmap::cli::Args;

fn main() {
    let args = Args::parse();
    println!("{args:#?}");
}
