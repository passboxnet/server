//! Talking to the identity provider: discovery, JWKS and the token
//! endpoint. Requests run on the blocking pool with `ureq` (rustls and the
//! platform's certificate store), without redirects, with a timeout and a
//! size limit. Response bodies are never passed on to API clients; errors
//! are reduced to codes, so the "test connection" feature cannot be used
//! to read internal services.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use passbox_core::oidc::{self, Jwks};
use serde::{Deserialize, Serialize};

/// Largest response accepted from the identity provider.
const MAX_RESPONSE_LEN: u64 = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

static ALLOW_HTTP_LOOPBACK: AtomicBool = AtomicBool::new(false);

/// Allows `http://` issuers on loopback addresses (`localhost`,
/// `127.0.0.1`, `[::1]`) for development and tests. Off by default; the
/// server turns it on when `PASSBOX_SSO_ALLOW_HTTP_LOOPBACK=1`.
pub fn allow_http_loopback(allow: bool) {
    ALLOW_HTTP_LOOPBACK.store(allow, Ordering::Relaxed);
}

pub(crate) fn init_from_env() {
    if std::env::var("PASSBOX_SSO_ALLOW_HTTP_LOOPBACK").is_ok_and(|v| v == "1" || v == "true") {
        allow_http_loopback(true);
    }
}

/// Why talking to the provider failed. The codes are part of the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// Not an `https://` URL (or `http://` on loopback when allowed).
    InsecureUrl,
    /// Could not connect, TLS failed or the request timed out.
    Unreachable,
    /// The provider answered with an error status.
    Status(u16),
    /// The answer was not the JSON we expected.
    InvalidResponse,
    /// The discovery document names another issuer.
    IssuerMismatch,
    /// The provider does not support what Passbox needs.
    Unsupported,
}

impl FetchError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InsecureUrl => "sso_insecure_url",
            Self::Unreachable => "sso_unreachable",
            Self::Status(_) => "sso_http_error",
            Self::InvalidResponse => "sso_invalid_response",
            Self::IssuerMismatch => "sso_issuer_mismatch",
            Self::Unsupported => "sso_unsupported_provider",
        }
    }

    pub fn message(self) -> String {
        match self {
            Self::InsecureUrl => "the identity provider must use https".into(),
            Self::Unreachable => "the identity provider could not be reached".into(),
            Self::Status(status) => format!("the identity provider answered with HTTP {status}"),
            Self::InvalidResponse => "the identity provider sent an unexpected answer".into(),
            Self::IssuerMismatch => {
                "the discovery document names another issuer; check the issuer URL".into()
            }
            Self::Unsupported => {
                "the identity provider does not support the authorization code flow with S256 PKCE and RS/PS/ES signatures"
                    .into()
            }
        }
    }
}

/// Checks that `url` is absolute `https://` (or loopback `http://` when
/// allowed) without user info or fragment.
pub fn check_url(url: &str) -> Result<(), FetchError> {
    let uri: ureq::http::Uri = url.parse().map_err(|_| FetchError::InsecureUrl)?;
    let host = uri.host().ok_or(FetchError::InsecureUrl)?;
    if url.contains('#') || uri.authority().is_some_and(|a| a.as_str().contains('@')) {
        return Err(FetchError::InsecureUrl);
    }
    match uri.scheme_str() {
        Some("https") => Ok(()),
        Some("http")
            if ALLOW_HTTP_LOOPBACK.load(Ordering::Relaxed)
                && matches!(host, "localhost" | "127.0.0.1" | "[::1]") =>
        {
            Ok(())
        }
        _ => Err(FetchError::InsecureUrl),
    }
}

fn is_loopback(url: &str) -> bool {
    url.parse::<ureq::http::Uri>()
        .ok()
        .and_then(|u| {
            u.host()
                .map(|h| matches!(h, "localhost" | "127.0.0.1" | "[::1]"))
        })
        .unwrap_or(false)
}

fn agent(url: &str) -> ureq::Agent {
    let mut config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(TIMEOUT))
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        );
    if is_loopback(url) {
        config = config.proxy(None);
    }
    config.build().into()
}

fn read(mut response: ureq::http::Response<ureq::Body>) -> Result<(u16, String), FetchError> {
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_LEN)
        .read_to_string()
        .map_err(|_| FetchError::InvalidResponse)?;
    Ok((status, body))
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, FetchError> + Send + 'static,
) -> Result<T, FetchError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| FetchError::Unreachable)?
}

/// GETs `url` and returns the body of a 200 answer.
pub async fn get(url: &str) -> Result<String, FetchError> {
    check_url(url)?;
    let url = url.to_owned();
    blocking(move || {
        let response = agent(&url)
            .get(&url)
            .header("accept", "application/json")
            .call()
            .map_err(|_| FetchError::Unreachable)?;
        let (status, body) = read(response)?;
        if status != 200 {
            return Err(FetchError::Status(status));
        }
        Ok(body)
    })
    .await
}

/// The parts of the discovery document Passbox uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

pub fn discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// Fetches and checks the discovery document of `issuer` (OpenID Connect
/// Discovery 1.0 §4): the issuer must match exactly, endpoints must be
/// https, and the provider must offer an asymmetric ID token algorithm and
/// (if it lists PKCE methods) S256.
pub async fn discover(issuer: &str) -> Result<Discovery, FetchError> {
    let body = get(&discovery_url(issuer)).await?;
    let discovery: Discovery =
        serde_json::from_str(&body).map_err(|_| FetchError::InvalidResponse)?;
    // A missing or extra trailing slash in what the admin typed is forgiven;
    // the document's issuer is what ID tokens must name exactly.
    if discovery.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err(FetchError::IssuerMismatch);
    }
    for url in [
        &discovery.authorization_endpoint,
        &discovery.token_endpoint,
        &discovery.jwks_uri,
    ] {
        check_url(url)?;
    }
    if !discovery.id_token_signing_alg_values_supported.is_empty()
        && !discovery
            .id_token_signing_alg_values_supported
            .iter()
            .any(|alg| oidc::SUPPORTED_ALGORITHMS.contains(&alg.as_str()))
    {
        return Err(FetchError::Unsupported);
    }
    if let Some(methods) = &discovery.code_challenge_methods_supported
        && !methods.iter().any(|m| m == "S256")
    {
        return Err(FetchError::Unsupported);
    }
    Ok(discovery)
}

/// Fetches and parses the provider's signing keys. Returns the raw JSON
/// (for caching) and the parsed set.
pub async fn fetch_jwks(jwks_uri: &str) -> Result<(String, Jwks), FetchError> {
    let body = get(jwks_uri).await?;
    let jwks = Jwks::parse(&body).map_err(|_| FetchError::InvalidResponse)?;
    if jwks.keys.is_empty() {
        return Err(FetchError::Unsupported);
    }
    Ok((body, jwks))
}

/// How the client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuth {
    /// HTTP Basic with the form-encoded client ID and secret (RFC 6749 §2.3.1).
    Basic,
    /// `client_id` and `client_secret` in the form body.
    Post,
    /// Public client: `client_id` only (PKCE protects the code).
    None,
}

impl TokenAuth {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "client_secret_basic" => Some(Self::Basic),
            "client_secret_post" => Some(Self::Post),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// `application/x-www-form-urlencoded` encoding of one value.
pub fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// URL query encoding of one value (spaces as `%20`).
pub fn query_encode(value: &str) -> String {
    form_encode(value).replace('+', "%20")
}

pub struct TokenRequest {
    pub token_endpoint: String,
    pub auth: TokenAuth,
    pub client_id: String,
    pub client_secret: String,
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: Option<String>,
}

/// Why the token request failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Fetch(FetchError),
    /// The provider rejected the code or the client (`invalid_grant`,
    /// `invalid_client`, …); the OAuth error code is kept for the logs.
    Rejected(String),
    /// The answer has no ID token (the `openid` scope is missing).
    NoIdToken,
}

/// Exchanges the authorization code for tokens and returns the ID token.
pub async fn exchange_code(request: TokenRequest) -> Result<String, TokenError> {
    check_url(&request.token_endpoint).map_err(TokenError::Fetch)?;
    let result = blocking(move || {
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", &request.code),
            ("redirect_uri", &request.redirect_uri),
            ("code_verifier", &request.code_verifier),
        ];
        let mut builder = agent(&request.token_endpoint)
            .post(&request.token_endpoint)
            .header("accept", "application/json");
        match request.auth {
            TokenAuth::Basic => {
                let credentials = format!(
                    "{}:{}",
                    form_encode(&request.client_id),
                    form_encode(&request.client_secret)
                );
                builder = builder.header(
                    "authorization",
                    format!(
                        "Basic {}",
                        data_encoding::BASE64.encode(credentials.as_bytes())
                    ),
                );
            }
            TokenAuth::Post => {
                form.push(("client_id", &request.client_id));
                form.push(("client_secret", &request.client_secret));
            }
            TokenAuth::None => form.push(("client_id", &request.client_id)),
        }
        let response = builder
            .send_form(form)
            .map_err(|_| FetchError::Unreachable)?;
        read(response)
    })
    .await
    .map_err(TokenError::Fetch)?;
    let (status, body) = result;
    if status != 200 {
        let error = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
            .unwrap_or_else(|| format!("http_{status}"));
        return Err(TokenError::Rejected(error.chars().take(64).collect()));
    }
    let tokens: TokenResponse =
        serde_json::from_str(&body).map_err(|_| TokenError::Fetch(FetchError::InvalidResponse))?;
    tokens.id_token.ok_or(TokenError::NoIdToken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_must_be_https() {
        assert!(check_url("https://login.example.com/realms/acme").is_ok());
        assert!(check_url("https://10.0.0.5:8443/oidc").is_ok());
        assert_eq!(
            check_url("http://idp.example.com"),
            Err(FetchError::InsecureUrl)
        );
        assert!(check_url("https://user:pw@idp.example.com").is_err());
        assert!(check_url("https://idp.example.com/#x").is_err());
        assert!(check_url("ftp://idp.example.com").is_err());
        assert!(check_url("idp.example.com").is_err());
    }

    #[test]
    fn encodes_forms() {
        assert_eq!(form_encode("a b&c=d/é"), "a+b%26c%3Dd%2F%C3%A9");
        assert_eq!(query_encode("openid email"), "openid%20email");
        assert_eq!(
            discovery_url("https://idp.example.com/"),
            "https://idp.example.com/.well-known/openid-configuration"
        );
    }
}
