//! Mail templates in English and German (formal "Sie").
//!
//! Every template is plain text plus a simple HTML version with the same
//! content. Templates take their parameters from a JSON object; unknown
//! parameters are ignored and missing ones are rendered as empty text, so a
//! mail queued by an older version still renders.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The kinds of mail the server sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Template {
    /// An invitation to the instance or an organization.
    ///
    /// Parameters: `inviter` (name or email), `link`, `expiresAt` (Unix ms),
    /// optional `organization` (its display name, if the inviting client
    /// chose to reveal it).
    Invitation,
    /// A sign-in from a device that had not signed in before.
    ///
    /// Parameters: `email`, `device`, `ip`, `time` (Unix ms).
    NewDevice,
    /// The master password was changed. Parameters: `email`, `device`, `ip`, `time`.
    MasterPasswordChanged,
    /// Two-factor sign-in was turned on, off or changed.
    ///
    /// Parameters: `email`, `change` (`enabled`, `disabled` or `changed`),
    /// `device`, `ip`, `time`.
    TwoFactorChanged,
    /// Emergency access was requested, granted or used (placeholder for C3).
    ///
    /// Parameters: `email`, `requester`, `event` (free text, optional), `link`.
    EmergencyAccess,
    /// Account recovery was requested or completed (placeholder for C1).
    ///
    /// Parameters: `email`, `event` (free text, optional), `link`.
    Recovery,
    /// A test mail sent from the administration. Parameters: `requestedBy`.
    Test,
}

impl Template {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invitation => "invitation",
            Self::NewDevice => "new_device",
            Self::MasterPasswordChanged => "master_password_changed",
            Self::TwoFactorChanged => "two_factor_changed",
            Self::EmergencyAccess => "emergency_access",
            Self::Recovery => "recovery",
            Self::Test => "test",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        serde_json::from_value(Value::String(value.to_owned())).ok()
    }
}

/// Languages mails are available in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    #[default]
    En,
    De,
}

impl Locale {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::De => "de",
        }
    }

    /// Parses `de`, `de-DE`, `en-US` and the like.
    pub fn parse(value: &str) -> Option<Self> {
        let base = value.trim().split(['-', '_']).next()?.to_ascii_lowercase();
        match base.as_str() {
            "en" => Some(Self::En),
            "de" => Some(Self::De),
            _ => None,
        }
    }

    /// Picks the first supported language of an `Accept-Language` header.
    pub fn from_accept_language(header: &str) -> Option<Self> {
        let mut candidates: Vec<(f32, Self)> = header
            .split(',')
            .filter_map(|part| {
                let mut pieces = part.split(';');
                let locale = Self::parse(pieces.next()?)?;
                let quality = pieces
                    .find_map(|p| p.trim().strip_prefix("q=")?.parse::<f32>().ok())
                    .unwrap_or(1.0);
                Some((quality, locale))
            })
            .collect();
        // Stable sort keeps the header order for equal weights.
        candidates.sort_by(|a, b| b.0.total_cmp(&a.0));
        candidates.first().map(|(_, locale)| *locale)
    }
}

/// A rendered mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub subject: String,
    pub text: String,
    pub html: String,
}

enum Block {
    Paragraph(String),
    /// A link shown as a button in HTML.
    Action {
        label: String,
        url: String,
    },
    /// Label/value pairs such as device and time.
    Details(Vec<(String, String)>),
    /// Small print at the end.
    Footer(String),
}

/// Context the server adds to every mail.
pub struct Context<'a> {
    pub instance_name: &'a str,
    /// Public URL of the web app (no trailing slash), if configured.
    pub public_url: Option<&'a str>,
}

fn param(params: &Value, name: &str) -> String {
    match params.get(name) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn time_param(params: &Value, name: &str, locale: Locale) -> String {
    params
        .get(name)
        .and_then(Value::as_i64)
        .map(|ms| format_time(ms, locale))
        .unwrap_or_default()
}

/// Formats Unix milliseconds as UTC: "2026-10-24 13:45 UTC" or "24.10.2026, 13:45 UTC".
pub fn format_time(unix_ms: i64, locale: Locale) -> String {
    let secs = unix_ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute) = (secs_of_day / 3600, (secs_of_day % 3600) / 60);
    match locale {
        Locale::En => format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC"),
        Locale::De => format!("{day:02}.{month:02}.{year:04}, {hour:02}:{minute:02} UTC"),
    }
}

/// Days since 1970-01-01 to (year, month, day), from Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn settings_link(ctx: &Context<'_>) -> Option<String> {
    ctx.public_url.map(|url| format!("{url}/#/settings"))
}

/// Renders `template` in `locale`.
pub fn render(template: Template, locale: Locale, params: &Value, ctx: &Context<'_>) -> Rendered {
    let instance = ctx.instance_name;
    let de = locale == Locale::De;
    let email = param(params, "email");
    let device_details = |params: &Value| {
        let device = param(params, "device");
        let ip = param(params, "ip");
        let time = time_param(params, "time", locale);
        let mut details = Vec::new();
        if !device.is_empty() {
            details.push((if de { "Gerät" } else { "Device" }.to_owned(), device));
        }
        if !ip.is_empty() {
            details.push((if de { "IP-Adresse" } else { "IP address" }.to_owned(), ip));
        }
        if !time.is_empty() {
            details.push((if de { "Zeitpunkt" } else { "Time" }.to_owned(), time));
        }
        Block::Details(details)
    };
    let mut blocks = Vec::new();
    // German mails continue after "Guten Tag," in lower case.
    let greeting = if de { "Guten Tag," } else { "Hello," };
    blocks.push(Block::Paragraph(greeting.to_owned()));

    let subject = match template {
        Template::Invitation => {
            let inviter = param(params, "inviter");
            let organization = param(params, "organization");
            let link = param(params, "link");
            let expires = time_param(params, "expiresAt", locale);
            blocks.push(Block::Paragraph(match (de, organization.is_empty()) {
                (true, true) => format!(
                    "{inviter} hat Sie zu {instance} eingeladen, dem Passwort-Manager Ihres Teams."
                ),
                (true, false) => format!(
                    "{inviter} hat Sie eingeladen, der Organisation „{organization}“ in {instance} beizutreten."
                ),
                (false, true) => {
                    format!("{inviter} has invited you to {instance}, your team's password manager.")
                }
                (false, false) => format!(
                    "{inviter} has invited you to join the organization “{organization}” on {instance}."
                ),
            }));
            blocks.push(Block::Paragraph(match (de, expires.is_empty()) {
                (true, true) => "Öffnen Sie den folgenden Link, um die Einladung anzunehmen.".to_owned(),
                (true, false) => format!(
                    "Öffnen Sie den folgenden Link, um die Einladung anzunehmen. Er ist bis {expires} gültig."
                ),
                (false, true) => "Open the link below to accept the invitation.".to_owned(),
                (false, false) => {
                    format!("Open the link below to accept the invitation. It is valid until {expires}.")
                }
            }));
            if !link.is_empty() {
                blocks.push(Block::Action {
                    label: if de {
                        "Einladung annehmen"
                    } else {
                        "Accept invitation"
                    }
                    .to_owned(),
                    url: link,
                });
            }
            blocks.push(Block::Footer(if de {
                "Falls Sie diese Einladung nicht erwartet haben, können Sie diese E-Mail ignorieren.".to_owned()
            } else {
                "If you did not expect this invitation, you can ignore this email.".to_owned()
            }));
            match (de, organization.is_empty()) {
                (true, true) => format!("Einladung zu {instance}"),
                (true, false) => format!("Einladung zu „{organization}“ in {instance}"),
                (false, true) => format!("You're invited to {instance}"),
                (false, false) => format!("You're invited to “{organization}” on {instance}"),
            }
        }
        Template::NewDevice => {
            blocks.push(Block::Paragraph(if de {
                format!(
                    "bei Ihrem {instance}-Konto {email} hat sich soeben ein neues Gerät angemeldet."
                )
            } else {
                format!("A new device just signed in to your {instance} account {email}.")
            }));
            blocks.push(device_details(params));
            blocks.push(Block::Paragraph(if de {
                "Wenn Sie das waren, müssen Sie nichts tun.".to_owned()
            } else {
                "If this was you, there is nothing you need to do.".to_owned()
            }));
            blocks.push(Block::Paragraph(if de {
                "Wenn Sie das nicht waren, ändern Sie sofort Ihr Master-Passwort und melden Sie das Gerät \
                 unter Einstellungen → Geräte ab. Für eine Anmeldung sind Ihr Master-Passwort und Ihr \
                 Geheimschlüssel nötig."
                    .to_owned()
            } else {
                "If this wasn't you, change your master password right away and sign out the device under \
                 Settings → Devices. Signing in requires your master password and your Secret Key."
                    .to_owned()
            }));
            if let Some(url) = settings_link(ctx) {
                blocks.push(Block::Action {
                    label: if de {
                        "Geräte prüfen"
                    } else {
                        "Review devices"
                    }
                    .to_owned(),
                    url: format!("{url}/devices"),
                });
            }
            blocks.push(Block::Footer(if de {
                "Sie können diese E-Mails unter Einstellungen → Benachrichtigungen abschalten."
                    .to_owned()
            } else {
                "You can turn off these emails under Settings → Notifications.".to_owned()
            }));
            if de {
                format!("Neue Anmeldung bei {instance}")
            } else {
                format!("New sign-in to {instance}")
            }
        }
        Template::MasterPasswordChanged => {
            blocks.push(Block::Paragraph(if de {
                format!("das Master-Passwort Ihres {instance}-Kontos {email} wurde geändert. Alle anderen Geräte wurden abgemeldet.")
            } else {
                format!("The master password of your {instance} account {email} was changed. All other devices were signed out.")
            }));
            blocks.push(device_details(params));
            blocks.push(Block::Paragraph(if de {
                "Wenn Sie das nicht waren, wenden Sie sich sofort an die Administration Ihrer Passbox-Instanz."
                    .to_owned()
            } else {
                "If this wasn't you, contact the administrators of your Passbox server right away.".to_owned()
            }));
            if de {
                format!("Ihr Master-Passwort für {instance} wurde geändert")
            } else {
                format!("Your {instance} master password was changed")
            }
        }
        Template::TwoFactorChanged => {
            let change = param(params, "change");
            blocks.push(Block::Paragraph(match (de, change.as_str()) {
                (true, "enabled") => format!("für Ihr {instance}-Konto {email} wurde die Anmeldung in zwei Schritten (2FA) eingeschaltet."),
                (true, "disabled") => format!("für Ihr {instance}-Konto {email} wurde die Anmeldung in zwei Schritten (2FA) ausgeschaltet."),
                (true, _) => format!("die Anmeldung in zwei Schritten (2FA) Ihres {instance}-Kontos {email} wurde geändert."),
                (false, "enabled") => format!("Two-step sign-in (2FA) was turned on for your {instance} account {email}."),
                (false, "disabled") => format!("Two-step sign-in (2FA) was turned off for your {instance} account {email}."),
                (false, _) => format!("The two-step sign-in (2FA) settings of your {instance} account {email} were changed."),
            }));
            blocks.push(device_details(params));
            blocks.push(Block::Paragraph(if de {
                "Wenn Sie das nicht waren, ändern Sie sofort Ihr Master-Passwort und prüfen Sie Ihre Geräte."
                    .to_owned()
            } else {
                "If this wasn't you, change your master password right away and review your devices.".to_owned()
            }));
            if de {
                format!("Anmeldung in zwei Schritten für {instance} geändert")
            } else {
                format!("Two-step sign-in for {instance} changed")
            }
        }
        Template::EmergencyAccess => {
            let requester = param(params, "requester");
            let event = param(params, "event");
            blocks.push(Block::Paragraph(if de {
                format!(
                    "{requester} hat Notfallzugang zu Ihrem {instance}-Konto {email} angefordert."
                )
            } else {
                format!(
                    "{requester} has requested emergency access to your {instance} account {email}."
                )
            }));
            if !event.is_empty() {
                blocks.push(Block::Paragraph(event));
            }
            push_link(
                &mut blocks,
                params,
                if de {
                    "Anfrage ansehen"
                } else {
                    "View request"
                },
            );
            blocks.push(Block::Paragraph(if de {
                "Wenn Sie die Anfrage nicht erwartet haben, lehnen Sie sie in Passbox ab."
                    .to_owned()
            } else {
                "If you did not expect this request, decline it in Passbox.".to_owned()
            }));
            if de {
                format!("Notfallzugang zu {instance} angefordert")
            } else {
                format!("Emergency access to {instance} requested")
            }
        }
        Template::Recovery => {
            let event = param(params, "event");
            blocks.push(Block::Paragraph(if de {
                format!(
                    "für Ihr {instance}-Konto {email} wurde eine Wiederherstellung angefordert."
                )
            } else {
                format!("Recovery of your {instance} account {email} was requested.")
            }));
            if !event.is_empty() {
                blocks.push(Block::Paragraph(event));
            }
            push_link(
                &mut blocks,
                params,
                if de {
                    "In Passbox öffnen"
                } else {
                    "Open in Passbox"
                },
            );
            blocks.push(Block::Paragraph(if de {
                "Wenn Sie das nicht waren, wenden Sie sich sofort an die Administration Ihrer Passbox-Instanz."
                    .to_owned()
            } else {
                "If this wasn't you, contact the administrators of your Passbox server right away.".to_owned()
            }));
            if de {
                format!("Wiederherstellung Ihres {instance}-Kontos")
            } else {
                format!("Recovery of your {instance} account")
            }
        }
        Template::Test => {
            let requested_by = param(params, "requestedBy");
            blocks.push(Block::Paragraph(if de {
                format!(
                    "dies ist eine Test-E-Mail von {instance}, angefordert von {requested_by}. Der E-Mail-Versand funktioniert."
                )
            } else {
                format!(
                    "This is a test email from {instance}, requested by {requested_by}. Sending email works."
                )
            }));
            if de {
                format!("Test-E-Mail von {instance}")
            } else {
                format!("Test email from {instance}")
            }
        }
    };
    blocks.push(Block::Footer(if de {
        format!("Diese E-Mail wurde automatisch von {instance} gesendet.")
    } else {
        format!("This email was sent automatically by {instance}.")
    }));

    Rendered {
        text: render_text(&blocks),
        html: render_html(&subject, &blocks, locale),
        subject,
    }
}

fn push_link(blocks: &mut Vec<Block>, params: &Value, label: &str) {
    let link = param(params, "link");
    if !link.is_empty() {
        blocks.push(Block::Action {
            label: label.to_owned(),
            url: link,
        });
    }
}

fn render_text(blocks: &[Block]) -> String {
    let mut out = Vec::new();
    for block in blocks {
        match block {
            Block::Paragraph(text) | Block::Footer(text) => out.push(text.clone()),
            Block::Action { label, url } => out.push(format!("{label}:\n{url}")),
            Block::Details(details) if !details.is_empty() => out.push(
                details
                    .iter()
                    .map(|(label, value)| format!("{label}: {value}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            Block::Details(_) => {}
        }
    }
    out.join("\n\n") + "\n"
}

/// Escapes text for HTML element content and attribute values.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn render_html(subject: &str, blocks: &[Block], locale: Locale) -> String {
    let mut body = String::new();
    for block in blocks {
        match block {
            Block::Paragraph(text) => {
                body.push_str(&format!(
                    "<p style=\"margin:0 0 16px\">{}</p>\n",
                    escape_html(text)
                ));
            }
            Block::Action { label, url } => {
                // Only web links become buttons; anything else stays text.
                if url.starts_with("https://") || url.starts_with("http://") {
                    body.push_str(&format!(
                        "<p style=\"margin:24px 0\"><a href=\"{}\" style=\"display:inline-block;padding:10px 18px;\
                         border-radius:8px;background:#2563eb;color:#ffffff;text-decoration:none;font-weight:600\">{}</a></p>\n\
                         <p style=\"margin:0 0 16px;font-size:12px;color:#6b7280;word-break:break-all\">{}</p>\n",
                        escape_html(url),
                        escape_html(label),
                        escape_html(url)
                    ));
                } else {
                    body.push_str(&format!(
                        "<p style=\"margin:0 0 16px\">{}: {}</p>\n",
                        escape_html(label),
                        escape_html(url)
                    ));
                }
            }
            Block::Details(details) if !details.is_empty() => {
                body.push_str("<table role=\"presentation\" style=\"margin:0 0 16px;border-collapse:collapse\">\n");
                for (label, value) in details {
                    body.push_str(&format!(
                        "<tr><td style=\"padding:2px 16px 2px 0;color:#6b7280\">{}</td><td style=\"padding:2px 0\">{}</td></tr>\n",
                        escape_html(label),
                        escape_html(value)
                    ));
                }
                body.push_str("</table>\n");
            }
            Block::Details(_) => {}
            Block::Footer(text) => {
                body.push_str(&format!(
                    "<p style=\"margin:24px 0 0;font-size:12px;color:#6b7280\">{}</p>\n",
                    escape_html(text)
                ));
            }
        }
    }
    format!(
        "<!doctype html>\n<html lang=\"{lang}\">\n<head><meta charset=\"utf-8\"><title>{title}</title></head>\n\
         <body style=\"margin:0;padding:24px;background:#f5f5f4;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;\
         font-size:15px;line-height:1.5;color:#1c1917\">\n\
         <div style=\"max-width:560px;margin:0 auto;padding:32px;background:#ffffff;border-radius:12px\">\n{body}</div>\n</body>\n</html>\n",
        lang = locale.as_str(),
        title = escape_html(subject),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const CTX: Context<'static> = Context {
        instance_name: "Passbox",
        public_url: Some("https://vault.example.com"),
    };

    const ALL: [Template; 7] = [
        Template::Invitation,
        Template::NewDevice,
        Template::MasterPasswordChanged,
        Template::TwoFactorChanged,
        Template::EmergencyAccess,
        Template::Recovery,
        Template::Test,
    ];

    #[test]
    fn every_template_renders_in_both_languages() {
        let params = json!({
            "email": "ada@example.com",
            "inviter": "admin@example.com",
            "link": "https://vault.example.com/#/?invite=abc",
            "expiresAt": 1_798_761_600_000_i64,
            "device": "Firefox on Linux",
            "ip": "203.0.113.7",
            "time": 1_761_313_500_000_i64,
            "requester": "bob@example.com",
            "requestedBy": "admin@example.com",
        });
        for template in ALL {
            for locale in [Locale::En, Locale::De] {
                let mail = render(template, locale, &params, &CTX);
                assert!(!mail.subject.is_empty());
                assert!(mail.text.contains("Passbox"), "{template:?}");
                assert!(mail.html.starts_with("<!doctype html>"));
                assert!(mail.html.contains(&format!("lang=\"{}\"", locale.as_str())));
                assert_eq!(Template::parse(template.as_str()), Some(template));
            }
        }
        let de = render(Template::NewDevice, Locale::De, &params, &CTX);
        assert!(de.text.contains("Gerät: Firefox on Linux"));
        assert!(de.text.contains("Zeitpunkt: 24.10.2025, 13:45 UTC"));
        assert!(de.text.starts_with("Guten Tag,\n\nbei Ihrem Passbox-Konto"));
        let en = render(Template::Invitation, Locale::En, &params, &CTX);
        assert!(en.text.contains("https://vault.example.com/#/?invite=abc"));
        assert!(en.text.contains("valid until 2027-01-01 00:00 UTC"));
    }

    #[test]
    fn html_escapes_parameters() {
        let params =
            json!({ "inviter": "<script>alert(1)</script>", "link": "javascript:alert(1)" });
        let mail = render(Template::Invitation, Locale::En, &params, &CTX);
        assert!(!mail.html.contains("<script>"));
        assert!(mail.html.contains("&lt;script&gt;"));
        // Non-web links never become clickable.
        assert!(!mail.html.contains("href=\"javascript:"));
    }

    #[test]
    fn locales_parse_from_tags_and_headers() {
        assert_eq!(Locale::parse("de-DE"), Some(Locale::De));
        assert_eq!(Locale::parse("EN"), Some(Locale::En));
        assert_eq!(Locale::parse("fr"), None);
        assert_eq!(
            Locale::from_accept_language("fr-FR, de;q=0.8, en;q=0.5"),
            Some(Locale::De)
        );
        assert_eq!(Locale::from_accept_language("fr"), None);
    }

    #[test]
    fn times_format_in_utc() {
        assert_eq!(format_time(0, Locale::En), "1970-01-01 00:00 UTC");
        assert_eq!(
            format_time(951_782_400_000, Locale::De),
            "29.02.2000, 00:00 UTC"
        );
    }
}
