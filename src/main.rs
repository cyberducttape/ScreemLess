mod analysis;
mod cli;
mod collector;
mod config_scanner;
mod dashboard;
mod db;
mod graph;
mod infrastructure;
mod models;
mod report;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("screamless=info".parse()?),
        )
        .init();

    let args = match cli::Args::try_parse() {
        Ok(args) => args,
        Err(error) => {
            let exit_code = cli::parse_error_exit_code(&error);
            let _ = error.print();
            std::process::exit(exit_code as i32);
        }
    };
    match cli::run(args).await {
        Ok(()) => Ok(()),
        Err(error) => {
            let code = cli::error_exit_code(&error);
            eprintln!("{}", error);
            std::process::exit(code as i32);
        }
    }
}
