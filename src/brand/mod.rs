//! The Passbox brand on the server's own surfaces: the assets it serves
//! (email logos, the typeface), the HTML pages it renders itself (start page
//! without a web vault, "not found", single sign-on errors) and the design
//! tokens they and the emails use. See docs/design/brand.md.
//!
//! Everything is served by the instance itself; no font or image CDN.

pub mod pages;
pub mod tokens;

use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::mail::Locale;
use crate::mail::templates::escape_html;

/// The email logo (mark and wordmark, 164 × 48 at 2×) for light backgrounds.
pub const LOGO_LIGHT_PNG: &[u8] =
    include_bytes!("../../../../packages/ui/brand/png/email-logo@2x.png");
/// The email logo for dark backgrounds.
pub const LOGO_DARK_PNG: &[u8] =
    include_bytes!("../../../../packages/ui/brand/png/email-logo-dark@2x.png");
/// Plus Jakarta Sans (variable, 200–800), Latin subset (OFL 1.1, see
/// assets/fonts/PlusJakartaSans-OFL.txt).
const FONT_LATIN: &[u8] =
    include_bytes!("../../assets/fonts/plus-jakarta-sans-latin-wght-normal.woff2");
/// Plus Jakarta Sans, Latin Extended subset.
const FONT_LATIN_EXT: &[u8] =
    include_bytes!("../../assets/fonts/plus-jakarta-sans-latin-ext-wght-normal.woff2");

/// Stable public paths of the brand assets.
pub const LOGO_LIGHT_PATH: &str = "/assets/mail/logo-light.png";
pub const LOGO_DARK_PATH: &str = "/assets/mail/logo-dark.png";
const FONT_LATIN_PATH: &str = "/assets/brand/plus-jakarta-sans-latin.woff2";
const FONT_LATIN_EXT_PATH: &str = "/assets/brand/plus-jakarta-sans-latin-ext.woff2";

/// The keyhole mark (packages/ui/brand/mark.svg) for inline use: the Solar
/// keyhole on the Marina signature gradient with a soft Sky glow.
pub const MARK_SVG: &str = concat!(
    r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32" aria-hidden="true">"##,
    r##"<defs><linearGradient id="pb" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#36596A"/>"##,
    r##"<stop offset="0.5" stop-color="#243E4B"/><stop offset="1" stop-color="#12232B"/></linearGradient>"##,
    r##"<radialGradient id="pb-glow" cx="0.22" cy="0.12" r="0.75"><stop offset="0" stop-color="#6EABC7" stop-opacity="0.38"/>"##,
    r##"<stop offset="1" stop-color="#6EABC7" stop-opacity="0"/></radialGradient></defs>"##,
    r##"<rect width="32" height="32" rx="9" fill="url(#pb)"/><rect width="32" height="32" rx="9" fill="url(#pb-glow)"/>"##,
    r##"<rect x="0.5" y="0.5" width="31" height="31" rx="8.5" fill="none" stroke="#fff" stroke-opacity="0.14"/>"##,
    r##"<circle cx="16" cy="13.4" r="4.2" fill="#FFE26D"/>"##,
    r##"<path d="M14.2 16.2h3.6l1.1 6.9a.8.8 0 0 1-.8.9h-4.2a.8.8 0 0 1-.8-.9z" fill="#FFE26D"/></svg>"##
);

/// Routes for the brand assets. They are public and long-cacheable.
pub fn routes<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route(
            LOGO_LIGHT_PATH,
            get(|| async { asset(LOGO_LIGHT_PNG, "image/png") }),
        )
        .route(
            LOGO_DARK_PATH,
            get(|| async { asset(LOGO_DARK_PNG, "image/png") }),
        )
        .route(
            FONT_LATIN_PATH,
            get(|| async { asset(FONT_LATIN, "font/woff2") }),
        )
        .route(
            FONT_LATIN_EXT_PATH,
            get(|| async { asset(FONT_LATIN_EXT, "font/woff2") }),
        )
}

fn asset(bytes: &'static [u8], content_type: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=604800"),
            ),
            // Fonts may be loaded by pages on other origins (a web vault
            // served elsewhere); the files are public anyway.
            (
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_static("*"),
            ),
        ],
        bytes,
    )
        .into_response()
}

/// A page the server renders itself.
pub struct Page<'a> {
    pub locale: Locale,
    pub status: StatusCode,
    /// The name the admins gave this server.
    pub instance_name: &'a str,
    /// Small overline above the title ("404", "Single Sign-on").
    pub eyebrow: String,
    pub title: String,
    pub paragraphs: Vec<String>,
    /// A value to show in a monospace well (an address to copy).
    pub code: Option<String>,
    /// A pill button: label and target (only same-site or http(s) links).
    pub action: Option<(String, String)>,
}

impl Page<'_> {
    pub fn into_response(self) -> Response {
        let status = self.status;
        (
            status,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                ),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            self.render(),
        )
            .into_response()
    }

    /// The page as HTML: the backdrop gradient, a panel with bezel, the
    /// dotted grid frame with corner dots, the logo and a pill button.
    pub fn render(&self) -> String {
        let mut body = String::new();
        for paragraph in &self.paragraphs {
            body.push_str(&format!("<p>{}</p>\n", escape_html(paragraph)));
        }
        if let Some(code) = &self.code {
            body.push_str(&format!(
                "<p class=\"well\"><code>{}</code></p>\n",
                escape_html(code)
            ));
        }
        if let Some((label, href)) = &self.action
            && (href.starts_with('/') && !href.starts_with("//")
                || href.starts_with("https://")
                || href.starts_with("http://"))
        {
            body.push_str(&format!(
                "<p class=\"actions\"><a class=\"pill\" href=\"{}\">{}</a></p>\n",
                escape_html(href),
                escape_html(label)
            ));
        }
        let footer = match self.locale {
            Locale::De => format!("{} · ein Passbox-Server", escape_html(self.instance_name)),
            Locale::En => format!("{} · a Passbox server", escape_html(self.instance_name)),
        };
        format!(
            "<!doctype html>\n<html lang=\"{lang}\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <meta name=\"color-scheme\" content=\"light dark\">\n<meta name=\"robots\" content=\"noindex\">\n\
             <title>{page_title}</title>\n<link rel=\"icon\" href=\"{favicon}\">\n\
             <style>{css}</style>\n</head>\n<body>\n<main class=\"stage\">\n<div class=\"bezel\">\n\
             <div class=\"panel\">\n<div class=\"frame\">\n\
             <span class=\"rule top\" aria-hidden=\"true\"></span>\n\
             <div class=\"brand\">{mark}<span>Passbox</span></div>\n\
             <p class=\"eyebrow\">{eyebrow}</p>\n<h1>{title}</h1>\n{body}\
             <span class=\"rule bottom\" aria-hidden=\"true\"></span>\n</div>\n\
             <footer>{footer}</footer>\n</div>\n</div>\n</main>\n</body>\n</html>\n",
            lang = self.locale.as_str(),
            title = escape_html(&self.title),
            page_title = if self.title.contains(self.instance_name) {
                escape_html(&self.title)
            } else {
                format!(
                    "{} · {}",
                    escape_html(&self.title),
                    escape_html(self.instance_name)
                )
            },
            eyebrow = escape_html(&self.eyebrow),
            favicon = favicon_data_url(),
            css = page_css(),
            mark = MARK_SVG,
        )
    }
}

fn favicon_data_url() -> String {
    let mut out = String::from("data:image/svg+xml,");
    for c in MARK_SVG.chars() {
        match c {
            '<' => out.push_str("%3C"),
            '>' => out.push_str("%3E"),
            '#' => out.push_str("%23"),
            '"' => out.push('\''),
            c => out.push(c),
        }
    }
    out
}

/// CSS custom properties for one theme.
fn theme_vars(t: &tokens::Theme) -> String {
    format!(
        "--canvas:{};--surface:{};--sunken:{};--border:{};--border-strong:{};--text:{};\
         --muted:{};--subtle:{};--accent:{};--accent-hover:{};--accent-pressed:{};--accent-edge:{};\
         --accent-contrast:{};--focus:{};",
        t.canvas,
        t.surface,
        t.surface_sunken,
        t.border,
        t.border_strong,
        t.text,
        t.text_muted,
        t.text_subtle,
        t.accent,
        t.accent_hover,
        t.accent_pressed,
        t.accent_edge,
        t.accent_contrast,
        t.focus,
    )
}

fn page_css() -> String {
    use tokens::{DARK, FONT_MONO, FONT_SANS, GRADIENT_BACKDROP, LIGHT, palette, radius};
    // Same film grain as the `grain` utility in packages/ui/src/tokens.css.
    const GRAIN: &str = "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3CfeColorMatrix values='0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 0.05 0'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E\")";
    format!(
        r#"
@font-face{{font-family:"Plus Jakarta Sans";font-style:normal;font-weight:200 800;font-display:swap;src:url({latin}) format("woff2");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}}
@font-face{{font-family:"Plus Jakarta Sans";font-style:normal;font-weight:200 800;font-display:swap;src:url({latin_ext}) format("woff2");unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF}}
:root{{{light}color-scheme:light dark}}
@media (prefers-color-scheme:dark){{:root{{{dark}}}}}
*{{box-sizing:border-box}}
html,body{{margin:0;min-height:100%}}
body{{min-height:100vh;font-family:{sans};font-size:15px;line-height:1.55;color:var(--text);background:radial-gradient(90% 50% at 50% -5%,{glow_sky},transparent 70%),radial-gradient(50% 40% at 90% 100%,{glow_solar},transparent 70%),{backdrop};background-color:{marina_lip};-webkit-font-smoothing:antialiased}}
body::after{{content:"";position:fixed;inset:0;pointer-events:none;background-image:{grain}}}
.stage{{position:relative;z-index:1;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:48px 16px}}
.bezel{{width:100%;max-width:560px;padding:10px;border-radius:{bezel_radius}px;background:rgba(219,239,249,.14);box-shadow:inset 0 0 0 1px rgba(255,255,255,.16),0 30px 80px -20px rgba(0,0,0,.6)}}
.panel{{border-radius:{panel}px;background:var(--canvas);overflow:hidden}}
.frame{{position:relative;margin:0 28px;padding:40px 28px 36px;background:radial-gradient(circle,var(--border-strong) .6px,transparent .9px) 0 0/1px 4px repeat-y,radial-gradient(circle,var(--border-strong) .6px,transparent .9px) 100% 0/1px 4px repeat-y}}
.rule{{position:absolute;left:-28px;right:-28px;height:1px;background:radial-gradient(circle,var(--border-strong) .6px,transparent .9px) 0 0/4px 1px repeat-x}}
.rule.top{{top:20px}}.rule.bottom{{bottom:0}}
.rule::before,.rule::after{{content:"";position:absolute;top:-2.5px;width:6px;height:6px;border-radius:50%;background:var(--subtle)}}
.rule::before{{left:25px}}.rule::after{{right:25px}}
.brand{{display:flex;align-items:center;gap:10px;margin:8px 0 32px;font-weight:700;font-size:18px;letter-spacing:-.02em}}
.brand svg{{width:32px;height:32px;flex:none}}
.eyebrow{{margin:0 0 10px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}}
h1{{margin:0 0 14px;font-size:28px;line-height:1.18;font-weight:600;letter-spacing:-.02em}}
p{{margin:0 0 14px;color:var(--muted)}}
.well{{margin:18px 0;padding:12px 16px;border-radius:{control}px;background:var(--sunken);box-shadow:inset 0 0 0 1px var(--border)}}
.well code{{font-family:{mono};font-size:13px;color:var(--text);word-break:break-all}}
.actions{{margin:24px 0 8px}}
.pill{{display:inline-flex;align-items:center;min-height:44px;padding:0 22px;border-radius:{pill}px;background:var(--accent);color:var(--accent-contrast);font-weight:600;font-size:14px;text-decoration:none;box-shadow:0 2px 0 0 var(--accent-edge)}}
.pill:hover{{background:var(--accent-hover);box-shadow:0 2px 0 0 var(--accent-edge),0 10px 24px -10px var(--accent-edge)}}
.pill:active{{background:var(--accent-pressed);box-shadow:none;transform:translateY(1px)}}
.pill:focus-visible{{outline:2px solid var(--focus);outline-offset:2px}}
footer{{padding:16px 56px 22px;font-size:12px;color:var(--subtle)}}
@media (max-width:480px){{.frame{{margin:0 16px;padding:36px 18px 28px}}.rule{{left:-16px;right:-16px}}.rule::before{{left:13px}}.rule::after{{right:13px}}footer{{padding:14px 34px 18px}}h1{{font-size:24px}}}}
"#,
        latin = FONT_LATIN_PATH,
        latin_ext = FONT_LATIN_EXT_PATH,
        light = theme_vars(&LIGHT),
        dark = theme_vars(&DARK),
        sans = FONT_SANS,
        mono = FONT_MONO,
        backdrop = GRADIENT_BACKDROP,
        glow_sky = palette::GLOW_SKY,
        glow_solar = palette::GLOW_SOLAR,
        marina_lip = palette::MARINA_LIP,
        grain = GRAIN,
        bezel_radius = radius::PANEL + 10,
        panel = radius::PANEL,
        control = radius::CONTROL,
        pill = radius::PILL,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> Page<'static> {
        Page {
            locale: Locale::De,
            status: StatusCode::NOT_FOUND,
            instance_name: "Acme <Tresor>",
            eyebrow: "404".to_owned(),
            title: "Seite nicht gefunden".to_owned(),
            paragraphs: vec!["<b>nicht</b> da".to_owned()],
            code: Some("https://vault.example.com".to_owned()),
            action: Some(("Zur Startseite".to_owned(), "/".to_owned())),
        }
    }

    #[test]
    fn pages_carry_the_brand_and_escape_text() {
        let html = page().render();
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("lang=\"de\""));
        assert!(html.contains("color-scheme"));
        assert!(html.contains("prefers-color-scheme:dark"));
        assert!(html.contains(tokens::GRADIENT_BACKDROP));
        assert!(html.contains(FONT_LATIN_PATH));
        assert!(html.contains("class=\"rule top\""));
        assert!(html.contains("class=\"pill\" href=\"/\""));
        assert!(html.contains("Acme &lt;Tresor&gt;"));
        assert!(html.contains("&lt;b&gt;nicht&lt;/b&gt;"));
        // Everything comes from the instance: no external hosts.
        assert!(!html.contains("https://fonts."));
        assert!(!html.contains("cdn"));
    }

    #[test]
    fn foreign_and_script_links_never_become_buttons() {
        for href in ["javascript:alert(1)", "//evil.example.com"] {
            let mut p = page();
            p.action = Some(("x".to_owned(), href.to_owned()));
            assert!(!p.render().contains("class=\"pill\""), "{href}");
        }
    }

    #[test]
    fn served_logos_are_the_brand_pngs() {
        for png in [LOGO_LIGHT_PNG, LOGO_DARK_PNG] {
            assert_eq!(&png[1..4], b"PNG");
        }
        assert_eq!(&FONT_LATIN[..4], b"wOF2");
        assert_eq!(&FONT_LATIN_EXT[..4], b"wOF2");
    }
}
