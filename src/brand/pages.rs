//! The pages the server renders itself when no web vault is installed
//! (`PASSBOX_WEB_DIR` unset): a start page and "not found". API clients get
//! a plain 404 as before.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

use super::Page;
use crate::mail::{Locale, request_locale};
use crate::state::AppState;

/// Whether the client wants a web page (a browser), not data.
fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

/// The instance name and the language for a page.
pub async fn context(state: &AppState, headers: &HeaderMap) -> (String, Locale) {
    match crate::instance::load_settings_from(&state.db).await {
        Ok(settings) => (
            settings.instance_name,
            request_locale(None, headers).unwrap_or(settings.default_locale),
        ),
        Err(_) => (
            "Passbox".to_owned(),
            request_locale(None, headers).unwrap_or_default(),
        ),
    }
}

/// The address apps should connect to: the public URL, else the Host header.
fn server_address(state: &AppState, headers: &HeaderMap) -> Option<String> {
    if let Some(url) = state.mailer.public_url() {
        return Some(url.to_owned());
    }
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let valid = !host.is_empty()
        && host.len() <= 255
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    let local =
        host.starts_with("localhost") || host.starts_with("127.") || host.starts_with("[::1]");
    let scheme = if local { "http" } else { "https" };
    valid.then(|| format!("{scheme}://{host}"))
}

/// Fallback for paths no route handles, without a web vault.
pub async fn fallback(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    if uri.path().starts_with("/api/") || !wants_html(&headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (instance, locale) = context(&state, &headers).await;
    let de = locale == Locale::De;
    if uri.path() == "/" {
        return Page {
            locale,
            status: StatusCode::OK,
            instance_name: &instance,
            eyebrow: "Server".to_owned(),
            title: if de {
                format!("{instance} ist bereit")
            } else {
                format!("{instance} is running")
            },
            paragraphs: vec![if de {
                "Auf diesem Server ist kein Web-Tresor installiert. Verbinden Sie die Passbox-Apps \
                 oder die Browser-Erweiterung mit dieser Adresse:"
                    .to_owned()
            } else {
                "This server has no web vault installed. Connect the Passbox apps or the browser \
                 extension to this address:"
                    .to_owned()
            }],
            code: server_address(&state, &headers),
            action: None,
        }
        .into_response();
    }
    Page {
        locale,
        status: StatusCode::NOT_FOUND,
        instance_name: &instance,
        eyebrow: "404".to_owned(),
        title: if de {
            "Seite nicht gefunden"
        } else {
            "Page not found"
        }
        .to_owned(),
        paragraphs: vec![if de {
            "Diese Adresse gibt es auf diesem Passbox-Server nicht. Prüfen Sie den Link oder \
             beginnen Sie auf der Startseite."
                .to_owned()
        } else {
            "This address does not exist on this Passbox server. Check the link or start from \
             the home page."
                .to_owned()
        }],
        code: None,
        action: Some((
            if de {
                "Zur Startseite"
            } else {
                "Go to the home page"
            }
            .to_owned(),
            "/".to_owned(),
        )),
    }
    .into_response()
}
