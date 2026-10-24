use clap::Parser;
use passbox_server::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();
    passbox_server::telemetry::init(config.log_format);
    passbox_server::serve(config).await
}
