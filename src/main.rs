mod cli;
mod db;
mod collector;
mod models;
mod report;
mod analysis;
mod config_scanner;
mod graph;
mod dashboard;
mod infrastructure;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("screamless=info".parse()?),
        )
        .init();

    let args = cli::Args::parse();
    cli::run(args).await
}
