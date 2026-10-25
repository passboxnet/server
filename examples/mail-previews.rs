//! Writes every mail template in English and German as HTML and plain text,
//! for looking at the layout in a browser or a mail client.
//!
//! ```sh
//! cargo run -p passbox-server --example mail-previews -- /tmp/mail-previews
//! ```
//!
//! The logos are written next to the files and referenced by file name
//! instead of `cid:` (real mails attach them inline).

use std::path::PathBuf;

use passbox_server::mail::layout::{INLINE_IMAGES, with_image_urls};
use passbox_server::mail::templates::{Context, render};
use passbox_server::mail::{Locale, Template};
use serde_json::json;

const TEMPLATES: [Template; 18] = [
    Template::Invitation,
    Template::NewDevice,
    Template::MasterPasswordChanged,
    Template::TwoFactorChanged,
    Template::EmergencyAccess,
    Template::EmergencyAccessInvited,
    Template::EmergencyAccessApproved,
    Template::EmergencyAccessDenied,
    Template::EmergencyAccessUsed,
    Template::Recovery,
    Template::RecoveryRequested,
    Template::RecoveryApproved,
    Template::RecoveryDenied,
    Template::RecoveryUsed,
    Template::RecoveryCodeCreated,
    Template::Test,
    Template::BreachMonitorCode,
    Template::BreachMonitorAlert,
];

fn main() -> std::io::Result<()> {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "mail-previews".to_owned()),
    );
    std::fs::create_dir_all(&dir)?;
    for image in &INLINE_IMAGES {
        std::fs::write(dir.join(image.file_name), image.bytes)?;
    }
    // Invented sample values.
    let params = json!({
        "email": "ada@example.com",
        "inviter": "Grace Hopper",
        "organization": "Beispiel GmbH",
        "link": "https://vault.example.com/#/settings/emergency",
        "expiresAt": 1_798_761_600_000_i64,
        "device": "Firefox 132 on Linux",
        "ip": "203.0.113.7",
        "time": 1_761_313_500_000_i64,
        "change": "enabled",
        "requester": "Grace Hopper",
        "grantor": "Grace Hopper",
        "grantee": "Grace Hopper",
        "waitDays": 7,
        "releaseAt": 1_761_918_300_000_i64,
        "member": "ada@example.com",
        "approver": "admin@example.com",
        "method": "org",
        "requestedBy": "admin@example.com",
        "code": "482 913",
        "minutes": 30,
        "monitored": "ada@example.com",
        "breaches": "Example Forum (2025)",
        "count": 1,
    });
    let ctx = Context {
        instance_name: "Passbox",
        public_url: Some("https://vault.example.com"),
    };
    let mut index =
        String::from("<!doctype html><meta charset=\"utf-8\"><title>Mail previews</title><ul>\n");
    for template in TEMPLATES {
        for locale in [Locale::De, Locale::En] {
            let mail = render(template, locale, &params, &ctx);
            let name = format!("{}.{}", template.as_str(), locale.as_str());
            let html = with_image_urls(&mail.html, |image| image.file_name.to_owned());
            std::fs::write(dir.join(format!("{name}.html")), html)?;
            std::fs::write(
                dir.join(format!("{name}.txt")),
                format!("Subject: {}\n\n{}", mail.subject, mail.text),
            )?;
            index.push_str(&format!(
                "<li><a href=\"{name}.html\">{name}</a> – {}</li>\n",
                passbox_server::mail::templates::escape_html(&mail.subject)
            ));
        }
    }
    index.push_str("</ul>\n");
    std::fs::write(dir.join("index.html"), index)?;
    println!("wrote {}", dir.display());
    Ok(())
}
