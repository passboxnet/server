use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;

/// Initializes logging. The level is controlled by `RUST_LOG` (default: `info`).
pub fn init(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        LogFormat::Pretty => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
}
