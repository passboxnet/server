//! Fetches website icons with the server's own fetcher, for the bundled
//! icons of popular sites (`scripts/update-site-icons.mjs`, which runs this
//! example). Not part of the server.
//!
//! Reads domains from stdin (one per line) and writes one JSON object per
//! domain to stdout, in input order:
//!
//! ```text
//! {"domain":"example.com","contentType":"image/png","source":"https://…","bytes":"<base64>"}
//! {"domain":"example.org","miss":true}
//! ```
//!
//! The same rules as the server apply (domain validation, https only,
//! public addresses, checked redirects, 200 KB, raster images whose bytes
//! match their type). With `HTTPS_PROXY` set it connects through that proxy
//! and checks every host with the system resolver first.
//!
//!   cargo run -p passbox-server --example fetch-site-icons -- --threads 32 < domains.txt

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use data_encoding::BASE64;
use passbox_server::api::icons::{HttpIconFetcher, IconFetcher, normalize_domain};

fn main() -> anyhow::Result<()> {
    let mut threads = 32usize;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--threads" => {
                threads = args
                    .next()
                    .and_then(|n| n.parse().ok())
                    .filter(|n| *n > 0)
                    .ok_or_else(|| anyhow::anyhow!("--threads needs a positive number"))?;
            }
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    let proxy = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .ok()
        .filter(|p| !p.trim().is_empty());
    let fetcher = Arc::new(match &proxy {
        Some(proxy) => HttpIconFetcher::with_proxy(proxy)?,
        None => HttpIconFetcher::new(),
    });

    let domains: Vec<String> = std::io::stdin()
        .lock()
        .lines()
        .map_while(Result::ok)
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect();
    let results: Arc<Vec<Mutex<Option<String>>>> =
        Arc::new(domains.iter().map(|_| Mutex::new(None)).collect());
    let domains = Arc::new(domains);
    let next = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));

    let workers: Vec<_> = (0..threads)
        .map(|_| {
            let (fetcher, domains, results, next, done) = (
                fetcher.clone(),
                domains.clone(),
                results.clone(),
                next.clone(),
                done.clone(),
            );
            std::thread::spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    let Some(input) = domains.get(index) else {
                        break;
                    };
                    let line = match normalize_domain(input) {
                        None => {
                            serde_json::json!({ "domain": input, "miss": true, "invalid": true })
                        }
                        Some(domain) => match fetcher.fetch_with_source(&domain) {
                            Some(found) => serde_json::json!({
                                "domain": input,
                                "contentType": found.icon.content_type,
                                "source": found.source_url,
                                "bytes": BASE64.encode(&found.icon.bytes),
                            }),
                            None => serde_json::json!({ "domain": input, "miss": true }),
                        },
                    };
                    *results[index].lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(line.to_string());
                    let finished = done.fetch_add(1, Ordering::SeqCst) + 1;
                    if finished % 100 == 0 {
                        eprintln!("{finished}/{}", domains.len());
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        let _ = worker.join();
    }
    let mut out = std::io::stdout().lock();
    for result in results.iter() {
        if let Some(line) = result.lock().unwrap_or_else(|e| e.into_inner()).take() {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}
