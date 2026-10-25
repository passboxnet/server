//! The HTML layout every mail shares ("Passbox Night", docs/design/brand.md).
//!
//! Email clients are not browsers: the layout uses nested tables and inline
//! styles, so it renders the same in Outlook, Gmail and Apple Mail. The light
//! theme is inline; clients that support `prefers-color-scheme` (Apple Mail,
//! iOS Mail, Outlook for Mac, some Android clients) switch to the dark theme
//! through the `<style>` block. Signature elements:
//!
//! - the logo (mark and wordmark) as inline images (`cid:`), a light and a
//!   dark version, so no remote image has to be loaded; the alt text keeps
//!   the wordmark readable when images are off;
//! - a slim band in the signature gradient on top of the panel;
//! - the panel (24 px radius) with dotted guides and corner dots;
//! - a pill-shaped primary button;
//! - a footer with the instance and why the mail was sent.

use super::templates::{Block, Context, Locale, escape_html};
use crate::brand::tokens::{
    DARK, FONT_SANS, GRADIENT_SIGNATURE, GRADIENT_SIGNATURE_FALLBACK, LIGHT, Theme, radius,
};

/// An image attached to every mail and referenced as `cid:{content_id}`.
pub struct InlineImage {
    pub content_id: &'static str,
    pub file_name: &'static str,
    pub bytes: &'static [u8],
}

/// The images the layout references (logo for light and dark backgrounds).
pub const INLINE_IMAGES: [InlineImage; 2] = [
    InlineImage {
        content_id: "logo-light@passbox",
        file_name: "logo-light.png",
        bytes: crate::brand::LOGO_LIGHT_PNG,
    },
    InlineImage {
        content_id: "logo-dark@passbox",
        file_name: "logo-dark.png",
        bytes: crate::brand::LOGO_DARK_PNG,
    },
];

/// Replaces the `cid:` references with other URLs (previews in a browser).
pub fn with_image_urls(html: &str, url: impl Fn(&InlineImage) -> String) -> String {
    let mut out = html.to_owned();
    for image in &INLINE_IMAGES {
        out = out.replace(&format!("cid:{}", image.content_id), &url(image));
    }
    out
}

/// Width of the mail in pixels (the content column of most clients).
const WIDTH: u32 = 600;
/// Distance from the panel edge to the dotted guides.
const GUTTER: u32 = 24;

/// Dark-theme overrides. `!important` beats the inline light styles.
fn dark_css(d: &Theme) -> String {
    let rules = format!(
        ".pb-canvas{{background:{canvas}!important}}\
         .pb-card{{background:{surface}!important;border-color:{border}!important}}\
         .pb-text{{color:{text}!important}}\
         .pb-muted{{color:{muted}!important}}\
         .pb-subtle{{color:{subtle}!important}}\
         .pb-link{{color:{link}!important}}\
         .pb-well{{background:{well}!important;border-color:{border}!important}}\
         .pb-rule{{border-color:{rule}!important}}\
         .pb-guide{{border-color:{rule}!important}}\
         .pb-dot{{background:{dot}!important}}\
         .pb-button{{background:{accent}!important}}\
         .pb-logo-light{{display:none!important}}\
         .pb-logo-dark{{display:block!important;max-height:none!important;overflow:visible!important}}",
        canvas = d.canvas,
        surface = d.surface,
        border = d.border,
        text = d.text,
        muted = d.text_muted,
        subtle = d.text_subtle,
        link = d.accent_text,
        well = d.surface_raised,
        rule = d.border_strong,
        dot = d.text_subtle,
        accent = d.accent,
    );
    // Outlook.com marks its dark mode with data-ogsc / data-ogsb.
    let outlook = rules
        .split_inclusive('}')
        .map(|rule| format!("[data-ogsc] {rule}"))
        .collect::<String>();
    format!("@media (prefers-color-scheme:dark){{{rules}}}{outlook}")
}

fn head_css() -> String {
    format!(
        ":root{{color-scheme:light dark;supported-color-schemes:light dark}}\
         body{{margin:0!important;padding:0!important;width:100%!important}}\
         a{{text-decoration:none}}\
         @media (max-width:620px){{.pb-outer{{padding:16px 8px!important}}\
         .pb-pad{{padding-left:20px!important;padding-right:20px!important}}\
         .pb-frame{{padding:24px 18px!important}}.pb-title{{font-size:20px!important}}}}\
         {dark}",
        dark = dark_css(&DARK),
    )
}

/// A row with a dotted hairline across the panel and small dots where the
/// guides cross it (the `GridFrame` motif).
fn rule_row(t: &Theme) -> String {
    let line = format!(
        "<td class=\"pb-rule\" style=\"font-size:0;line-height:0;border-top:1px dotted {c}\">&nbsp;</td>",
        c = t.border_strong
    );
    let edge = format!(
        "<td class=\"pb-rule\" width=\"{w}\" style=\"width:{w}px;font-size:0;line-height:0;border-top:1px dotted {c}\">&nbsp;</td>",
        w = GUTTER - 3,
        c = t.border_strong
    );
    let dot = format!(
        "<td width=\"6\" style=\"width:6px;font-size:0;line-height:0;vertical-align:top\">\
         <div class=\"pb-dot\" style=\"width:6px;height:6px;margin-top:-3px;border-radius:3px;background:{c};font-size:0;line-height:0\">&nbsp;</div></td>",
        c = t.text_subtle
    );
    format!(
        "<tr><td style=\"padding:0\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse\">\
         <tr>{edge}{dot}{line}{dot}{edge}</tr></table></td></tr>\n"
    )
}

/// The first paragraph after the greeting, shown by clients as preview text.
fn preheader(blocks: &[Block]) -> Option<&str> {
    blocks
        .iter()
        .filter_map(|block| match block {
            Block::Paragraph(text) => Some(text.as_str()),
            _ => None,
        })
        .nth(1)
}

/// Renders the blocks of a mail into the shared layout.
pub(super) fn render(subject: &str, blocks: &[Block], locale: Locale, ctx: &Context<'_>) -> String {
    let t = &LIGHT;
    let text_style = format!("color:{}", t.text);
    let mut content = String::new();
    let mut footers = Vec::new();
    for block in blocks {
        match block {
            Block::Paragraph(text) => content.push_str(&format!(
                "<p class=\"pb-text\" style=\"margin:0 0 16px;font-size:15px;line-height:1.6;{text_style}\">{}</p>\n",
                escape_html(text)
            )),
            Block::Action { label, url } => {
                // Only web links become buttons; anything else stays text.
                if url.starts_with("https://") || url.starts_with("http://") {
                    content.push_str(&format!(
                        "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:28px 0 12px;border-collapse:separate\">\
                         <tr><td class=\"pb-button\" align=\"center\" bgcolor=\"{accent}\" style=\"border-radius:{pill}px;background:{accent}\">\
                         <a href=\"{href}\" target=\"_blank\" style=\"display:inline-block;padding:13px 26px;border-radius:{pill}px;\
                         font-family:{font};font-size:15px;font-weight:600;line-height:20px;color:{contrast};text-decoration:none\">{label}</a>\
                         </td></tr></table>\n\
                         <p class=\"pb-subtle\" style=\"margin:0 0 16px;font-size:12px;line-height:1.5;color:{subtle};word-break:break-all\">\
                         <a class=\"pb-link\" href=\"{href}\" target=\"_blank\" style=\"color:{link};text-decoration:none\">{url_text}</a></p>\n",
                        accent = t.accent,
                        pill = radius::PILL,
                        font = escape_html(FONT_SANS),
                        contrast = t.accent_contrast,
                        subtle = t.text_subtle,
                        link = t.accent_text,
                        href = escape_html(url),
                        label = escape_html(label),
                        url_text = escape_html(url),
                    ));
                } else {
                    content.push_str(&format!(
                        "<p class=\"pb-text\" style=\"margin:0 0 16px;font-size:15px;line-height:1.6;{text_style}\">{}: {}</p>\n",
                        escape_html(label),
                        escape_html(url)
                    ));
                }
            }
            Block::Details(details) if !details.is_empty() => {
                content.push_str(&format!(
                    "<table role=\"presentation\" class=\"pb-well\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" \
                     style=\"margin:4px 0 20px;border-collapse:separate;background:{well};border:1px solid {border};border-radius:{r}px\">\
                     <tr><td style=\"padding:14px 18px\"><table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse\">\n",
                    well = t.surface_raised,
                    border = t.border,
                    r = radius::TILE,
                ));
                for (label, value) in details {
                    content.push_str(&format!(
                        "<tr><td class=\"pb-muted\" style=\"padding:3px 20px 3px 0;font-size:13px;line-height:1.5;color:{muted};vertical-align:top;white-space:nowrap\">{}</td>\
                         <td class=\"pb-text\" style=\"padding:3px 0;font-size:14px;line-height:1.5;font-weight:600;{text_style};word-break:break-word\">{}</td></tr>\n",
                        escape_html(label),
                        escape_html(value),
                        muted = t.text_muted,
                    ));
                }
                content.push_str("</table></td></tr></table>\n");
            }
            Block::Details(_) => {}
            Block::Footer(text) => footers.push(text.as_str()),
        }
    }
    let footer = footers
        .iter()
        .map(|text| {
            format!(
                "<p class=\"pb-subtle\" style=\"margin:0 0 6px;font-size:12px;line-height:1.5;color:{}\">{}</p>",
                t.text_subtle,
                escape_html(text)
            )
        })
        .collect::<String>();
    let instance = escape_html(ctx.instance_name);
    let below = match ctx.public_url {
        Some(url) => format!(
            "<strong class=\"pb-muted\" style=\"color:{muted};font-weight:600\">{instance}</strong> · \
             <a class=\"pb-link\" href=\"{href}\" target=\"_blank\" style=\"color:{link};text-decoration:none\">{shown}</a>",
            muted = t.text_muted,
            href = escape_html(url),
            link = t.accent_text,
            shown = escape_html(
                url.trim_start_matches("https://")
                    .trim_start_matches("http://")
            ),
        ),
        None => format!(
            "<strong class=\"pb-muted\" style=\"color:{};font-weight:600\">{instance}</strong>",
            t.text_muted
        ),
    };
    let tagline = match locale {
        Locale::De => "Passbox · Open Source, Ende-zu-Ende-verschlüsselt",
        Locale::En => "Passbox · open source, end-to-end encrypted",
    };
    let preheader = preheader(blocks)
        .map(|text| {
            format!(
                "<div style=\"display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all\">{}&#8203;</div>\n",
                escape_html(text)
            )
        })
        .unwrap_or_default();
    let rule = rule_row(t);
    let logo = |class: &str, cid: &str, hidden: bool| {
        let hide = if hidden {
            "display:none;max-height:0;overflow:hidden;mso-hide:all;"
        } else {
            "display:block;"
        };
        format!(
            "<img class=\"{class}\" src=\"cid:{cid}\" width=\"164\" height=\"48\" alt=\"Passbox\" \
             style=\"{hide}width:164px;height:48px;border:0;outline:none;font-family:{font};font-size:20px;font-weight:700;line-height:48px;color:{color}\">",
            font = escape_html(FONT_SANS),
            color = t.text,
        )
    };
    let logos = format!(
        "{}<!--[if !mso]><!-->{}<!--<![endif]-->",
        logo("pb-logo-light", INLINE_IMAGES[0].content_id, false),
        logo("pb-logo-dark", INLINE_IMAGES[1].content_id, true),
    );
    format!(
        "<!doctype html>\n<html lang=\"{lang}\" xmlns=\"http://www.w3.org/1999/xhtml\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"color-scheme\" content=\"light dark\">\n<meta name=\"supported-color-schemes\" content=\"light dark\">\n\
         <meta name=\"x-apple-disable-message-reformatting\">\n<title>{title}</title>\n<style>{css}</style>\n</head>\n\
         <body class=\"pb-canvas\" style=\"margin:0;padding:0;background:{canvas};font-family:{font}\">\n{preheader}\
         <table role=\"presentation\" class=\"pb-canvas\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" bgcolor=\"{canvas}\" style=\"background:{canvas};border-collapse:collapse\">\n\
         <tr><td class=\"pb-outer\" align=\"center\" style=\"padding:32px 16px\">\n\
         <table role=\"presentation\" width=\"{width}\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"width:100%;max-width:{width}px;border-collapse:collapse\">\n\
         <tr><td>\n\
         <table role=\"presentation\" class=\"pb-card\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" bgcolor=\"{surface}\" \
         style=\"border-collapse:separate;background:{surface};border:1px solid {border};border-radius:{panel}px;overflow:hidden\">\n\
         <tr><td bgcolor=\"{band_fallback}\" style=\"height:6px;font-size:0;line-height:0;background:{band_fallback};background-image:{band};border-radius:{panel}px {panel}px 0 0\">&nbsp;</td></tr>\n\
         <tr><td class=\"pb-pad\" style=\"padding:26px {gutter}px 22px\">{logos}</td></tr>\n\
         {rule}\
         <tr><td style=\"padding:0 {inset}px\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse\"><tr>\
         <td class=\"pb-frame pb-guide\" style=\"padding:30px 28px 14px;border-left:1px dotted {guide};border-right:1px dotted {guide};font-family:{font};{text_style}\">\n\
         <h1 class=\"pb-text pb-title\" style=\"margin:0 0 20px;font-family:{font};font-size:22px;line-height:1.25;font-weight:600;letter-spacing:-0.015em;{text_style}\">{title}</h1>\n\
         {content}</td></tr></table></td></tr>\n\
         {rule}\
         <tr><td class=\"pb-pad\" style=\"padding:20px {gutter}px 22px;font-family:{font}\">{footer}</td></tr>\n\
         </table>\n\
         </td></tr>\n\
         <tr><td align=\"center\" style=\"padding:20px 16px 8px;font-family:{font};font-size:12px;line-height:1.6;color:{subtle}\">\
         <p class=\"pb-subtle\" style=\"margin:0;color:{subtle}\">{below}</p>\
         <p class=\"pb-subtle\" style=\"margin:4px 0 0;color:{subtle}\">{tagline}</p></td></tr>\n\
         </table>\n</td></tr>\n</table>\n</body>\n</html>\n",
        lang = locale.as_str(),
        title = escape_html(subject),
        css = head_css(),
        canvas = t.canvas,
        surface = t.surface,
        border = t.border,
        subtle = t.text_subtle,
        guide = t.border_strong,
        font = escape_html(FONT_SANS),
        width = WIDTH,
        panel = radius::PANEL,
        band = GRADIENT_SIGNATURE,
        band_fallback = GRADIENT_SIGNATURE_FALLBACK,
        gutter = GUTTER,
        inset = GUTTER,
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::mail::Template;
    use crate::mail::templates::render as render_mail;

    const CTX: Context<'static> = Context {
        instance_name: "Acme Tresor",
        public_url: Some("https://vault.example.com"),
    };

    fn mail(locale: Locale) -> String {
        let params = json!({
            "inviter": "admin@example.com",
            "link": "https://vault.example.com/#/?invite=abc",
            "expiresAt": 1_798_761_600_000_i64,
        });
        render_mail(Template::Invitation, locale, &params, &CTX).html
    }

    #[test]
    fn layout_has_the_signature_elements() {
        let html = mail(Locale::De);
        // Dark-mode aware, readable in light clients.
        assert!(html.contains("<meta name=\"color-scheme\" content=\"light dark\">"));
        assert!(html.contains("@media (prefers-color-scheme:dark)"));
        assert!(html.contains(&format!("background:{}", LIGHT.canvas)));
        assert!(html.contains(&format!(
            ".pb-canvas{{background:{}!important}}",
            DARK.canvas
        )));
        // Logo as inline images, light and dark, with the wordmark as alt text.
        for image in &INLINE_IMAGES {
            assert!(html.contains(&format!("src=\"cid:{}\"", image.content_id)));
        }
        assert!(html.contains("alt=\"Passbox\""));
        // Signature gradient band with a solid fallback.
        assert!(html.contains(GRADIENT_SIGNATURE));
        assert!(html.contains(&format!("bgcolor=\"{GRADIENT_SIGNATURE_FALLBACK}\"")));
        // Panel radius, dotted guides and corner dots.
        assert!(html.contains(&format!("border-radius:{}px", radius::PANEL)));
        assert!(html.contains("border-left:1px dotted"));
        assert_eq!(html.matches("class=\"pb-dot\"").count(), 4);
        // Pill button that links to the invitation.
        assert!(html.contains("class=\"pb-button\""));
        assert!(html.contains(&format!("border-radius:{}px", radius::PILL)));
        assert!(html.contains(">Einladung annehmen</a>"));
        // Title, preview text and footer with the instance and the reason.
        assert!(html.contains("<title>Einladung zu Acme Tresor</title>"));
        assert!(html.contains("<h1 class=\"pb-text pb-title\""));
        assert!(html.contains("mso-hide:all\">admin@example.com hat Sie zu Acme Tresor"));
        assert!(html.contains(">Acme Tresor</strong>"));
        assert!(html.contains(">vault.example.com</a>"));
        assert!(html.contains("Falls Sie diese Einladung nicht erwartet haben"));
        assert!(html.contains("Diese E-Mail wurde automatisch von Acme Tresor gesendet."));
        // No remote resources: no external images, fonts or stylesheets.
        assert!(!html.contains("src=\"http"));
        assert!(!html.contains("<link"));
        assert!(!html.contains("@import"));
    }

    #[test]
    fn layout_is_table_based_and_balanced() {
        for locale in [Locale::En, Locale::De] {
            let html = mail(locale);
            for tag in ["table", "tr", "td", "p"] {
                let open = html.matches(&format!("<{tag}>")).count()
                    + html.matches(&format!("<{tag} ")).count();
                let close = html.matches(&format!("</{tag}>")).count();
                assert_eq!(open, close, "<{tag}> in {locale:?}");
            }
        }
    }

    #[test]
    fn previews_can_point_the_images_elsewhere() {
        let html = with_image_urls(&mail(Locale::En), |image| image.file_name.to_owned());
        assert!(html.contains("src=\"logo-light.png\""));
        assert!(html.contains("src=\"logo-dark.png\""));
        assert!(!html.contains("cid:"));
    }
}
