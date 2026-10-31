//! SCIM 2.0 provisioning (wave E3, RFC 7643/7644) under `/api/v1/scim/v2`,
//! authenticated with a bearer token per organization.
//!
//! What provisioning does in Passbox:
//!
//! - **Create or activate a user:** if the email belongs to a member, the
//!   SCIM user is linked; otherwise the server creates an invitation and
//!   mails it. The person joins by accepting it (or by signing in through
//!   the organization's SSO, which accepts it). Members are then **pending
//!   confirmation**: an admin's client must verify their key and seal the
//!   organization key, which the server cannot do.
//! - **Deactivate (`active: false`) or delete:** the membership is
//!   suspended and every session, device token, SSO proof and trusted
//!   device of the account ends immediately. Pending invitations are
//!   revoked. Reactivation restores the previous status. Removing the
//!   member (which rotates vault keys) is left to an admin.
//! - **Groups** are stored with their members and shown to admins. Passbox
//!   groups hold sealed keys, so mapping directory groups to them needs an
//!   admin client and is not automatic.

pub mod filter;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use passbox_core::encoding;
use passbox_core::sharing::objects::OrgRole;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgConnection;

use self::filter::{Attribute, Filter, Value as FilterValue};
use super::access;
use super::auth::{Session, record_event};
use super::sso::login::{end_access, hash, new_id};
use super::validate;
use crate::db::{OrgCredential, Public, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::mail::{Mailer, Template};
use crate::security::ClientIp;
use crate::state::AppState;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const MAX_BODY: usize = 1024 * 1024;
const MAX_PAGE: usize = 200;
/// Invitations created by provisioning are valid this long.
const INVITATION_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const MAX_TOKENS: i64 = 10;
/// Requests per token and minute.
const REQUESTS_PER_MINUTE: u32 = 600;

// --- Errors and responses -----------------------------------------------------------

/// A SCIM error response (`application/scim+json`).
#[derive(Debug)]
pub struct ScimError {
    status: StatusCode,
    scim_type: Option<&'static str>,
    detail: String,
}

impl ScimError {
    fn new(status: StatusCode, scim_type: Option<&'static str>, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type,
            detail: detail.into(),
        }
    }
    fn bad(scim_type: &'static str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some(scim_type), detail)
    }
    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, None, "resource not found")
    }
}

impl From<ApiError> for ScimError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::NotFound => Self::not_found(),
            ApiError::RateLimited(_) => {
                Self::new(StatusCode::TOO_MANY_REQUESTS, None, "too many requests")
            }
            ApiError::BadRequest(message) => Self::bad("invalidValue", message),
            other => {
                tracing::error!(error = ?other, "SCIM request failed");
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    "internal server error",
                )
            }
        }
    }
}

impl From<sqlx::Error> for ScimError {
    fn from(error: sqlx::Error) -> Self {
        ApiError::from(error).into()
    }
}

fn scim_json(status: StatusCode, body: Value) -> Response {
    let mut response = (status, body.to_string()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json"),
    );
    response
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let mut body = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.as_u16().to_string(),
            "detail": self.detail,
        });
        if let Some(scim_type) = self.scim_type {
            body["scimType"] = json!(scim_type);
        }
        scim_json(self.status, body)
    }
}

type ScimResult<T> = Result<T, ScimError>;

/// Unix milliseconds as an RFC 3339 UTC timestamp.
pub fn iso_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn base_url(state: &AppState) -> String {
    state
        .mailer
        .public_url()
        .map(|u| format!("{}/api/v1/scim/v2", u.trim_end_matches('/')))
        .unwrap_or_else(|| "/api/v1/scim/v2".into())
}

fn parse_body(body: &Bytes) -> ScimResult<Value> {
    if body.len() > MAX_BODY {
        return Err(ScimError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            None,
            "request too large",
        ));
    }
    serde_json::from_slice(body)
        .map_err(|_| ScimError::bad("invalidSyntax", "the body is not valid JSON"))
}

// --- Authentication -------------------------------------------------------------------

/// A request authenticated with an organization's SCIM token.
pub struct ScimAuth {
    org_id: String,
    /// The admin who created the token (named as the inviter).
    created_by: String,
}

impl FromRequestParts<AppState> for ScimAuth {
    type Rejection = ScimError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let unauthorized = || {
            ScimError::new(
                StatusCode::UNAUTHORIZED,
                None,
                "a valid SCIM bearer token is required",
            )
        };
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|t| !t.is_empty() && t.len() <= 128)
            .ok_or_else(unauthorized)?;
        let token_hash = hash(token);
        let now = now_ms();
        // The function resolves this token only; the request then runs in
        // the organization's SCIM context.
        let row: Option<(String, String, String, i64)> = sqlx::query!(
            r#"SELECT id AS "id!", org_id AS "org_id!", created_by AS "created_by!",
                      last_used_at AS "last_used_at!"
               FROM passbox.scim_token($1, $2)"#,
            &token_hash,
            now,
        )
        .map(|row| (row.id, row.org_id, row.created_by, row.last_used_at))
        .fetch_optional(&mut *state.db.public(Public::Meta).await?)
        .await?;
        let (id, org_id, created_by, last_used_at) = row.ok_or_else(unauthorized)?;
        if let Some(wait) = state.limiter.hit(
            &format!("scim:{id}"),
            REQUESTS_PER_MINUTE,
            std::time::Duration::from_secs(60),
        ) {
            return Err(ApiError::RateLimited(wait).into());
        }
        if now - last_used_at > 60_000 {
            let mut tx = state.db.as_org(OrgCredential::Scim, &org_id).await?;
            sqlx::query!(
                "UPDATE scim_tokens SET last_used_at = $1 WHERE id = $2",
                now,
                &id,
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }
        Ok(Self { org_id, created_by })
    }
}

// --- Discovery endpoints -------------------------------------------------------------------

pub async fn service_provider_config(State(state): State<AppState>, _auth: ScimAuth) -> Response {
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://github.com/passboxnet/passbox/blob/main/docs/architecture/sso.md",
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_PAGE },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": true },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "A SCIM token created in the organization's settings in Passbox",
                "primary": true,
            }],
            "meta": { "resourceType": "ServiceProviderConfig", "location": format!("{}/ServiceProviderConfig", base_url(&state)) },
        }),
    )
}

pub async fn resource_types(State(state): State<AppState>, _auth: ScimAuth) -> Response {
    let base = base_url(&state);
    let resources = json!([
        { "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User",
          "endpoint": "/Users", "schema": USER_SCHEMA, "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/User") } },
        { "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "Group", "name": "Group",
          "endpoint": "/Groups", "schema": GROUP_SCHEMA, "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/Group") } },
    ]);
    scim_json(
        StatusCode::OK,
        json!({ "schemas": [LIST_SCHEMA], "totalResults": 2, "startIndex": 1, "itemsPerPage": 2, "Resources": resources }),
    )
}

fn attribute(name: &str, kind: &str, required: bool, case_exact: bool, uniqueness: &str) -> Value {
    json!({
        "name": name, "type": kind, "multiValued": false, "required": required, "caseExact": case_exact,
        "mutability": if name == "id" { "readOnly" } else { "readWrite" }, "returned": "default", "uniqueness": uniqueness,
    })
}

pub async fn schemas(_auth: ScimAuth) -> Response {
    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": USER_SCHEMA, "name": "User", "description": "Passbox organization member",
        "attributes": [
            attribute("userName", "string", true, false, "server"),
            attribute("displayName", "string", false, false, "none"),
            attribute("externalId", "string", false, true, "none"),
            attribute("active", "boolean", false, false, "none"),
            { "name": "name", "type": "complex", "multiValued": false, "required": false, "subAttributes": [
                attribute("givenName", "string", false, false, "none"),
                attribute("familyName", "string", false, false, "none"),
            ] },
            { "name": "emails", "type": "complex", "multiValued": true, "required": false, "subAttributes": [
                attribute("value", "string", false, false, "none"),
                attribute("type", "string", false, false, "none"),
                attribute("primary", "boolean", false, false, "none"),
            ] },
        ],
    });
    let group = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": GROUP_SCHEMA, "name": "Group", "description": "Directory group",
        "attributes": [
            attribute("displayName", "string", true, false, "none"),
            attribute("externalId", "string", false, true, "none"),
            { "name": "members", "type": "complex", "multiValued": true, "required": false, "subAttributes": [
                attribute("value", "string", false, true, "none"),
                attribute("display", "string", false, false, "none"),
            ] },
        ],
    });
    scim_json(
        StatusCode::OK,
        json!({ "schemas": [LIST_SCHEMA], "totalResults": 2, "startIndex": 1, "itemsPerPage": 2, "Resources": [user, group] }),
    )
}

// --- Users -------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq)]
struct UserAttrs {
    user_name: String,
    external_id: String,
    email: String,
    display_name: String,
    given_name: String,
    family_name: String,
    active: bool,
}

#[derive(Debug, Clone)]
struct UserRow {
    id: String,
    attrs: UserAttrs,
    account_id: Option<String>,
    suspended_from: String,
    version: i64,
    created_at: i64,
    updated_at: i64,
}

type UserTuple = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    bool,
    Option<String>,
    String,
    i64,
    i64,
    i64,
);

fn user_from(row: UserTuple) -> UserRow {
    let (
        id,
        external_id,
        user_name,
        email,
        display_name,
        given_name,
        family_name,
        active,
        account_id,
        suspended_from,
        version,
        created_at,
        updated_at,
    ) = row;
    UserRow {
        id,
        attrs: UserAttrs {
            user_name,
            external_id,
            email,
            display_name,
            given_name,
            family_name,
            active,
        },
        account_id,
        suspended_from,
        version,
        created_at,
        updated_at,
    }
}

const USER_COLUMNS: &str = "id, external_id, user_name, email, display_name, given_name, family_name, active, \
                            account_id, suspended_from, version, created_at, updated_at";

async fn load_users(conn: &mut PgConnection, org_id: &str) -> ScimResult<Vec<UserRow>> {
    let rows: Vec<UserTuple> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {USER_COLUMNS} FROM scim_users WHERE org_id = $1 ORDER BY created_at, id"
    )))
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(user_from).collect())
}

async fn load_user(conn: &mut PgConnection, org_id: &str, id: &str) -> ScimResult<UserRow> {
    let row: Option<UserTuple> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {USER_COLUMNS} FROM scim_users WHERE org_id = $1 AND id = $2"
    )))
    .bind(org_id)
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(user_from).ok_or_else(ScimError::not_found)
}

async fn user_groups(conn: &mut PgConnection, user_id: &str) -> ScimResult<Vec<(String, String)>> {
    Ok(sqlx::query!(
        "SELECT scim_groups.id, scim_groups.display_name FROM scim_group_members \
         JOIN scim_groups ON scim_groups.id = scim_group_members.group_id \
         WHERE scim_group_members.user_id = $1 ORDER BY scim_groups.display_name",
        user_id,
    )
    .map(|row| (row.id, row.display_name))
    .fetch_all(&mut *conn)
    .await?)
}

fn user_json(base: &str, user: &UserRow, groups: &[(String, String)]) -> Value {
    let a = &user.attrs;
    let mut value = json!({
        "schemas": [USER_SCHEMA],
        "id": user.id,
        "userName": a.user_name,
        "active": a.active,
        "name": { "givenName": a.given_name, "familyName": a.family_name,
                  "formatted": format!("{} {}", a.given_name, a.family_name).trim() },
        "displayName": a.display_name,
        "emails": [{ "value": a.email, "type": "work", "primary": true }],
        "groups": groups.iter().map(|(id, name)| json!({ "value": id, "display": name, "$ref": format!("{base}/Groups/{id}") })).collect::<Vec<_>>(),
        "meta": {
            "resourceType": "User",
            "created": iso_time(user.created_at),
            "lastModified": iso_time(user.updated_at),
            "location": format!("{base}/Users/{}", user.id),
            "version": format!("W/\"{}\"", user.version),
        },
    });
    if !a.external_id.is_empty() {
        value["externalId"] = json!(a.external_id);
    }
    value
}

fn text(value: &Value, max: usize) -> ScimResult<String> {
    match value {
        Value::String(s) => Ok(s
            .chars()
            .filter(|c| !c.is_control())
            .take(max)
            .collect::<String>()
            .trim()
            .to_owned()),
        Value::Null => Ok(String::new()),
        _ => Err(ScimError::bad("invalidValue", "expected a string")),
    }
}

fn boolean(value: &Value) -> ScimResult<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Ok(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(ScimError::bad("invalidValue", "active must be a boolean")),
    }
}

/// The primary (or first) email of an `emails` array.
fn primary_email(value: &Value) -> Option<String> {
    let list = value.as_array()?;
    list.iter()
        .find(|e| {
            e.get("primary")
                .is_some_and(|p| p == &json!(true) || p == &json!("true"))
        })
        .or_else(|| list.first())
        .and_then(|e| e.get("value"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Sets one attribute by (normalized) path. Unknown attributes (title,
/// addresses, enterprise extension, …) are accepted and ignored.
fn set_user_attr(attrs: &mut UserAttrs, path: &str, value: &Value) -> ScimResult<()> {
    match filter::normalize(path).as_str() {
        "username" => attrs.user_name = text(value, 254)?,
        "externalid" => attrs.external_id = text(value, 255)?,
        "displayname" => attrs.display_name = text(value, 200)?,
        "active" => attrs.active = boolean(value)?,
        "name.givenname" => attrs.given_name = text(value, 100)?,
        "name.familyname" => attrs.family_name = text(value, 100)?,
        "name" => {
            if let Some(given) = value.get("givenName") {
                attrs.given_name = text(given, 100)?;
            }
            if let Some(family) = value.get("familyName") {
                attrs.family_name = text(family, 100)?;
            }
        }
        "emails.value" => {
            attrs.email = match value {
                Value::Array(_) => primary_email(value).unwrap_or_default(),
                other => text(other, 254)?,
            }
        }
        _ => {}
    }
    Ok(())
}

fn clear_user_attr(attrs: &mut UserAttrs, path: &str) {
    match filter::normalize(path).as_str() {
        "externalid" => attrs.external_id.clear(),
        "displayname" => attrs.display_name.clear(),
        "name.givenname" => attrs.given_name.clear(),
        "name.familyname" => attrs.family_name.clear(),
        "name" => {
            attrs.given_name.clear();
            attrs.family_name.clear();
        }
        _ => {}
    }
}

/// Attributes from a full resource (POST, PUT).
fn user_attrs(body: &Value) -> ScimResult<UserAttrs> {
    let object = body
        .as_object()
        .ok_or_else(|| ScimError::bad("invalidSyntax", "expected a User object"))?;
    let mut attrs = UserAttrs {
        active: true,
        ..UserAttrs::default()
    };
    for (key, value) in object {
        if key == "emails" {
            attrs.email = primary_email(value).unwrap_or_default();
        } else if key != "schemas" && key != "id" && key != "meta" {
            set_user_attr(&mut attrs, key, value)?;
        }
    }
    finish_user(&mut attrs)?;
    Ok(attrs)
}

fn finish_user(attrs: &mut UserAttrs) -> ScimResult<()> {
    if attrs.user_name.is_empty() {
        return Err(ScimError::bad("invalidValue", "userName is required"));
    }
    if attrs.email.is_empty() && attrs.user_name.contains('@') {
        attrs.email = attrs.user_name.clone();
    }
    attrs.email = validate::email(&attrs.email).map_err(|_| {
        ScimError::bad(
            "invalidValue",
            "the user needs a valid email (userName or emails)",
        )
    })?;
    Ok(())
}

fn user_lookup<'a>(user: &'a UserRow) -> impl Fn(&str) -> Option<Attribute> + 'a {
    move |attr| {
        let a = &user.attrs;
        let string = |s: &str, case_exact: bool| {
            (!s.is_empty()).then(|| Attribute {
                values: vec![FilterValue::Str(s.to_owned())],
                case_exact,
            })
        };
        match attr {
            "id" => string(&user.id, true),
            "username" => string(&a.user_name, false),
            "externalid" => string(&a.external_id, true),
            "displayname" => string(&a.display_name, false),
            "emails.value" => string(&a.email, false),
            "name.givenname" => string(&a.given_name, false),
            "name.familyname" => string(&a.family_name, false),
            "active" => Some(Attribute {
                values: vec![FilterValue::Bool(a.active)],
                case_exact: false,
            }),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    start_index: Option<i64>,
    #[serde(default)]
    count: Option<i64>,
}

fn page<T>(items: Vec<T>, query: &ListQuery) -> (usize, usize, Vec<T>) {
    let total = items.len();
    let start = usize::try_from(query.start_index.unwrap_or(1).max(1)).unwrap_or(1);
    let count =
        usize::try_from(query.count.unwrap_or(100).clamp(0, MAX_PAGE as i64)).unwrap_or(100);
    let items = items.into_iter().skip(start - 1).take(count).collect();
    (total, start, items)
}

fn parsed_filter(query: &ListQuery) -> ScimResult<Option<Filter>> {
    query
        .filter
        .as_deref()
        .filter(|f| !f.trim().is_empty())
        .map(|f| filter::parse(f).map_err(|e| ScimError::bad("invalidFilter", e)))
        .transpose()
}

fn list_response(total: usize, start: usize, resources: Vec<Value>) -> Response {
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    )
}

pub async fn list_users(
    State(state): State<AppState>,
    auth: ScimAuth,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    let filter = parsed_filter(&query)?;
    let mut conn = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
    let users: Vec<UserRow> = load_users(&mut conn, &auth.org_id)
        .await?
        .into_iter()
        .filter(|u| {
            filter
                .as_ref()
                .is_none_or(|f| filter::matches(f, &user_lookup(u)))
        })
        .collect();
    let (total, start, users) = page(users, &query);
    let base = base_url(&state);
    let mut resources = Vec::with_capacity(users.len());
    for user in &users {
        let groups = user_groups(&mut conn, &user.id).await?;
        resources.push(user_json(&base, user, &groups));
    }
    Ok(list_response(total, start, resources))
}

pub async fn get_user(
    State(state): State<AppState>,
    auth: ScimAuth,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    let mut conn = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
    let user = load_user(&mut conn, &auth.org_id, &id).await?;
    let groups = user_groups(&mut conn, &id).await?;
    Ok(scim_json(
        StatusCode::OK,
        user_json(&base_url(&state), &user, &groups),
    ))
}

/// Brings the organization in line with a provisioned user's state.
async fn apply_user(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    auth: &ScimAuth,
    user: &mut UserRow,
    previous_email: Option<&str>,
    locale: crate::mail::Locale,
    mails: &mut bool,
) -> ScimResult<Vec<String>> {
    let org_id = &auth.org_id;
    let now = now_ms();
    let mut ended = Vec::new();
    // An email change leaves the old invitation behind.
    if let Some(old) = previous_email.filter(|old| *old != user.attrs.email) {
        revoke_invitations(tx, org_id, old).await?;
    }
    // The person may not be a member yet: the function finds the account.
    let account: Option<String> = sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM passbox.account_by_email($1)"#,
        &user.attrs.email,
    )
    .fetch_optional(&mut **tx)
    .await?;
    let membership = match &account {
        Some(account_id) => access::membership(tx, org_id, account_id).await?,
        None => None,
    };
    if user.attrs.active {
        match (&account, &membership) {
            (Some(account_id), Some(m)) => {
                user.account_id = Some(account_id.clone());
                if m.status == "suspended" && !user.suspended_from.is_empty() {
                    set_member_status(tx, org_id, account_id, &user.suspended_from).await?;
                }
                user.suspended_from.clear();
            }
            _ => {
                user.account_id = None;
                ensure_invitation(state, tx, auth, &user.attrs.email, locale, now).await?;
                *mails = true;
            }
        }
    } else {
        revoke_invitations(tx, org_id, &user.attrs.email).await?;
        if let (Some(account_id), Some(m)) = (&account, &membership) {
            if m.role == OrgRole::Owner {
                return Err(ScimError::bad(
                    "mutability",
                    "the organization's owner cannot be deactivated through SCIM",
                ));
            }
            if m.status != "suspended" {
                user.suspended_from = m.status.clone();
                set_member_status(tx, org_id, account_id, "suspended").await?;
            }
            end_access(tx, account_id).await?;
            ended.push(account_id.clone());
        }
    }
    Ok(ended)
}

async fn set_member_status(
    conn: &mut PgConnection,
    org_id: &str,
    account_id: &str,
    status: &str,
) -> ScimResult<()> {
    let seq: i64 = sqlx::query_scalar!(
        "UPDATE counters SET value = value + 1 WHERE name = 'change_seq' RETURNING value"
    )
    .fetch_one(&mut *conn)
    .await?;
    sqlx::query!(
        "UPDATE org_members SET status = $1, seq = $2, updated_at = $3 WHERE org_id = $4 AND account_id = $5",
        status,
        seq,
        now_ms(),
        org_id,
        account_id,
    )
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn revoke_invitations(conn: &mut PgConnection, org_id: &str, email: &str) -> ScimResult<()> {
    sqlx::query!(
        "UPDATE org_invitations SET status = 'revoked' WHERE org_id = $1 AND email = $2 AND status = 'pending'",
        org_id,
        email,
    )
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Creates (and mails) an invitation unless one is pending.
async fn ensure_invitation(
    state: &AppState,
    conn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    auth: &ScimAuth,
    email: &str,
    locale: crate::mail::Locale,
    now: i64,
) -> ScimResult<()> {
    let pending: Option<i64> = sqlx::query_scalar!(
        "SELECT 1::BIGINT AS \"one!\" FROM org_invitations WHERE org_id = $1 AND email = $2 AND status = 'pending' AND expires_at > $3",
        &auth.org_id,
        email,
        now,
    )
    .fetch_optional(&mut **conn)
    .await?;
    if pending.is_some() {
        return Ok(());
    }
    let invitation_id = new_id()?;
    let token = encoding::encode(
        &passbox_core::random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?,
    );
    let expires_at = now + INVITATION_TTL_MS;
    sqlx::query!(
        "INSERT INTO org_invitations (id, org_id, email, role, token_hash, status, created_by, created_at, \
         expires_at, accepted_by, accepted_at) VALUES ($1, $2, $3, 'member', $4, 'pending', $5, $6, $7, NULL, NULL)",
        &invitation_id,
        &auth.org_id,
        email,
        hash(&token),
        &auth.created_by,
        now,
        expires_at,
    )
    .execute(&mut **conn)
    .await?;
    let inviter: String = sqlx::query_scalar!(
        r#"SELECT email AS "email!" FROM account_directory WHERE id = $1"#,
        &auth.created_by,
    )
    .fetch_optional(&mut **conn)
    .await?
    .unwrap_or_default();
    let link = state
        .mailer
        .public_url()
        .map(|base| format!("{}/invite/{token}", base.trim_end_matches('/')))
        .unwrap_or_default();
    Mailer::enqueue_in(
        conn,
        email,
        Template::Invitation,
        locale,
        &json!({ "inviter": inviter, "organizationKind": "team", "link": link, "expiresAt": expires_at }),
    )
    .await
    .map_err(|e| ScimError::from(ApiError::Internal(e)))?;
    Ok(())
}

async fn save_user(
    conn: &mut PgConnection,
    org_id: &str,
    user: &UserRow,
    insert: bool,
) -> ScimResult<()> {
    let a = &user.attrs;
    let key = a.user_name.to_lowercase();
    let taken: Option<String> = sqlx::query_scalar!(
        "SELECT id FROM scim_users WHERE org_id = $1 AND user_name_key = $2",
        org_id,
        &key,
    )
    .fetch_optional(&mut *conn)
    .await?;
    if taken.is_some_and(|id| id != user.id) {
        return Err(ScimError::new(
            StatusCode::CONFLICT,
            Some("uniqueness"),
            "a user with this userName exists",
        ));
    }
    if insert {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO scim_users ({USER_COLUMNS}, org_id, user_name_key) VALUES \
             ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"
        )))
        .bind(&user.id)
        .bind(&a.external_id)
        .bind(&a.user_name)
        .bind(&a.email)
        .bind(&a.display_name)
        .bind(&a.given_name)
        .bind(&a.family_name)
        .bind(a.active)
        .bind(&user.account_id)
        .bind(&user.suspended_from)
        .bind(user.version)
        .bind(user.created_at)
        .bind(user.updated_at)
        .bind(org_id)
        .bind(&key)
        .execute(&mut *conn)
        .await?;
    } else {
        sqlx::query!(
            "UPDATE scim_users SET external_id = $1, user_name = $2, user_name_key = $3, email = $4, display_name = $5, \
             given_name = $6, family_name = $7, active = $8, account_id = $9, suspended_from = $10, version = $11, \
             updated_at = $12 WHERE id = $13 AND org_id = $14",
            &a.external_id,
            &a.user_name,
            &key,
            &a.email,
            &a.display_name,
            &a.given_name,
            &a.family_name,
            a.active,
            user.account_id.as_deref(),
            &user.suspended_from,
            user.version,
            user.updated_at,
            &user.id,
            org_id,
        )
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

async fn deprovision_events(state: &AppState, accounts: &[String]) {
    for account_id in accounts {
        if let Err(error) = record_event(
            state,
            account_id,
            "org_membership_deprovisioned",
            "SCIM",
            "",
            "",
        )
        .await
        {
            tracing::warn!(?error, "could not record deprovisioning");
        }
    }
}

/// Stores a user (create or update) and applies the side effects in one
/// transaction.
async fn write_user(
    state: &AppState,
    auth: &ScimAuth,
    mut user: UserRow,
    previous: Option<&UserRow>,
) -> ScimResult<UserRow> {
    let mut tx = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
    let locale = crate::instance::load_settings(&mut tx)
        .await
        .map_err(ApiError::Internal)?
        .default_locale;
    let mut mails = false;
    let ended = apply_user(
        state,
        &mut tx,
        auth,
        &mut user,
        previous.map(|p| p.attrs.email.as_str()),
        locale,
        &mut mails,
    )
    .await?;
    save_user(&mut tx, &auth.org_id, &user, previous.is_none()).await?;
    tx.commit().await?;
    if mails {
        state.mailer.wake();
    }
    deprovision_events(state, &ended).await;
    Ok(user)
}

pub async fn create_user(
    State(state): State<AppState>,
    auth: ScimAuth,
    body: Bytes,
) -> ScimResult<Response> {
    let attrs = user_attrs(&parse_body(&body)?)?;
    let now = now_ms();
    let user = UserRow {
        id: new_id()?,
        attrs,
        account_id: None,
        suspended_from: String::new(),
        version: 1,
        created_at: now,
        updated_at: now,
    };
    let user = write_user(&state, &auth, user, None).await?;
    let base = base_url(&state);
    let mut response = scim_json(StatusCode::CREATED, user_json(&base, &user, &[]));
    if let Ok(location) = HeaderValue::from_str(&format!("{base}/Users/{}", user.id)) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}

async fn update_user(
    state: &AppState,
    auth: &ScimAuth,
    id: &str,
    attrs: UserAttrs,
) -> ScimResult<Response> {
    let mut conn = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
    let previous = load_user(&mut conn, &auth.org_id, id).await?;
    drop(conn);
    if previous.attrs == attrs {
        let mut conn = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
        let groups = user_groups(&mut conn, id).await?;
        return Ok(scim_json(
            StatusCode::OK,
            user_json(&base_url(state), &previous, &groups),
        ));
    }
    let mut user = previous.clone();
    user.attrs = attrs;
    user.version += 1;
    user.updated_at = now_ms();
    let user = write_user(state, auth, user, Some(&previous)).await?;
    let mut conn = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
    let groups = user_groups(&mut conn, id).await?;
    Ok(scim_json(
        StatusCode::OK,
        user_json(&base_url(state), &user, &groups),
    ))
}

pub async fn replace_user(
    State(state): State<AppState>,
    auth: ScimAuth,
    Path(id): Path<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let attrs = user_attrs(&parse_body(&body)?)?;
    update_user(&state, &auth, &id, attrs).await
}

/// The operations of a PATCH request.
fn operations(body: &Value) -> ScimResult<Vec<(String, Option<String>, Value)>> {
    if !body
        .get("schemas")
        .and_then(Value::as_array)
        .is_some_and(|s| s.iter().any(|v| v == PATCH_SCHEMA))
    {
        return Err(ScimError::bad(
            "invalidSyntax",
            "expected a PatchOp request",
        ));
    }
    let ops = body
        .get("Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| ScimError::bad("invalidSyntax", "Operations is required"))?;
    if ops.len() > 100 {
        return Err(ScimError::bad(
            "tooMany",
            "at most 100 operations per request",
        ));
    }
    ops.iter()
        .map(|op| {
            let name = op
                .get("op")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
                .filter(|o| ["add", "replace", "remove"].contains(&o.as_str()))
                .ok_or_else(|| {
                    ScimError::bad("invalidSyntax", "op must be add, replace or remove")
                })?;
            let path = op.get("path").and_then(Value::as_str).map(str::to_owned);
            let value = op.get("value").cloned().unwrap_or(Value::Null);
            if name != "remove" && value.is_null() {
                return Err(ScimError::bad(
                    "invalidValue",
                    "add and replace need a value",
                ));
            }
            if name == "remove" && path.is_none() {
                return Err(ScimError::bad("noTarget", "remove needs a path"));
            }
            Ok((name, path, value))
        })
        .collect()
}

pub async fn patch_user(
    State(state): State<AppState>,
    auth: ScimAuth,
    Path(id): Path<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let ops = operations(&parse_body(&body)?)?;
    let mut conn = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
    let mut attrs = load_user(&mut conn, &auth.org_id, &id).await?.attrs;
    drop(conn);
    for (op, path, value) in ops {
        match (op.as_str(), path) {
            ("remove", Some(path)) => clear_user_attr(&mut attrs, &path),
            (_, Some(path)) => set_user_attr(&mut attrs, &path, &value)?,
            (_, None) => {
                let object = value.as_object().ok_or_else(|| {
                    ScimError::bad("invalidValue", "a value without path must be an object")
                })?;
                for (key, value) in object {
                    set_user_attr(&mut attrs, key, value)?;
                }
            }
        }
    }
    finish_user(&mut attrs)?;
    update_user(&state, &auth, &id, attrs).await
}

/// DELETE: deactivates like `active: false` (membership suspended, access
/// ended) and forgets the SCIM user. An admin removes the member.
pub async fn delete_user(
    State(state): State<AppState>,
    auth: ScimAuth,
    Path(id): Path<String>,
) -> ScimResult<StatusCode> {
    let mut conn = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
    let previous = load_user(&mut conn, &auth.org_id, &id).await?;
    drop(conn);
    let mut user = previous.clone();
    user.attrs.active = false;
    let mut tx = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
    let locale = crate::instance::load_settings(&mut tx)
        .await
        .map_err(ApiError::Internal)?
        .default_locale;
    let mut mails = false;
    let ended = apply_user(&state, &mut tx, &auth, &mut user, None, locale, &mut mails).await?;
    sqlx::query!(
        "DELETE FROM scim_users WHERE id = $1 AND org_id = $2",
        &id,
        &auth.org_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    deprovision_events(&state, &ended).await;
    Ok(StatusCode::NO_CONTENT)
}

// --- Groups ------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct GroupRow {
    id: String,
    external_id: String,
    display_name: String,
    members: Vec<(String, String)>,
    version: i64,
    created_at: i64,
    updated_at: i64,
}

async fn group_members(
    conn: &mut PgConnection,
    group_id: &str,
) -> ScimResult<Vec<(String, String)>> {
    Ok(sqlx::query!(
        "SELECT scim_users.id, scim_users.user_name FROM scim_group_members \
         JOIN scim_users ON scim_users.id = scim_group_members.user_id \
         WHERE scim_group_members.group_id = $1 ORDER BY scim_users.user_name",
        group_id,
    )
    .map(|row| (row.id, row.user_name))
    .fetch_all(&mut *conn)
    .await?)
}

async fn load_groups(
    conn: &mut PgConnection,
    org_id: &str,
    id: Option<&str>,
) -> ScimResult<Vec<GroupRow>> {
    let rows: Vec<(String, String, String, i64, i64, i64)> = sqlx::query!(
        "SELECT id, external_id, display_name, version, created_at, updated_at FROM scim_groups \
         WHERE org_id = $1 AND ($2 = '' OR id = $3) ORDER BY created_at, id",
        org_id,
        id.unwrap_or(""),
        id.unwrap_or(""),
    )
    .map(|row| {
        (
            row.id,
            row.external_id,
            row.display_name,
            row.version,
            row.created_at,
            row.updated_at,
        )
    })
    .fetch_all(&mut *conn)
    .await?;
    let mut groups = Vec::with_capacity(rows.len());
    for (id, external_id, display_name, version, created_at, updated_at) in rows {
        let members = group_members(conn, &id).await?;
        groups.push(GroupRow {
            id,
            external_id,
            display_name,
            members,
            version,
            created_at,
            updated_at,
        });
    }
    Ok(groups)
}

fn group_json(base: &str, group: &GroupRow) -> Value {
    let mut value = json!({
        "schemas": [GROUP_SCHEMA],
        "id": group.id,
        "displayName": group.display_name,
        "members": group.members.iter().map(|(id, name)| json!({ "value": id, "display": name, "$ref": format!("{base}/Users/{id}") })).collect::<Vec<_>>(),
        "meta": {
            "resourceType": "Group",
            "created": iso_time(group.created_at),
            "lastModified": iso_time(group.updated_at),
            "location": format!("{base}/Groups/{}", group.id),
            "version": format!("W/\"{}\"", group.version),
        },
    });
    if !group.external_id.is_empty() {
        value["externalId"] = json!(group.external_id);
    }
    value
}

fn member_ids(value: &Value) -> ScimResult<Vec<String>> {
    let list = match value {
        Value::Array(list) => list.clone(),
        Value::Object(_) => vec![value.clone()],
        _ => return Err(ScimError::bad("invalidValue", "members must be a list")),
    };
    list.iter()
        .map(|m| {
            m.get("value")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| ScimError::bad("invalidValue", "a member needs a value"))
        })
        .collect()
}

/// The member ID in `members[value eq "id"]`.
fn member_filter_id(path: &str) -> Option<String> {
    let inner = path.split_once('[')?.1.rsplit_once(']')?.0;
    match filter::parse(inner).ok()? {
        Filter::Compare {
            attr,
            op,
            value: FilterValue::Str(id),
        } if attr.eq_ignore_ascii_case("value") && op == "eq" => Some(id),
        _ => None,
    }
}

async fn save_group(
    state: &AppState,
    auth: &ScimAuth,
    group: &GroupRow,
    members: &[String],
    insert: bool,
) -> ScimResult<()> {
    let mut tx = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
    if insert {
        sqlx::query!(
            "INSERT INTO scim_groups (id, org_id, external_id, display_name, version, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &group.id,
            &auth.org_id,
            &group.external_id,
            &group.display_name,
            group.version,
            group.created_at,
            group.updated_at,
        )
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query!(
            "UPDATE scim_groups SET external_id = $1, display_name = $2, version = $3, updated_at = $4 \
             WHERE id = $5 AND org_id = $6",
            &group.external_id,
            &group.display_name,
            group.version,
            group.updated_at,
            &group.id,
            &auth.org_id,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "DELETE FROM scim_group_members WHERE group_id = $1",
            &group.id,
        )
        .execute(&mut *tx)
        .await?;
    }
    for member in members {
        let known: Option<i64> = sqlx::query_scalar!(
            "SELECT 1::BIGINT AS \"one!\" FROM scim_users WHERE id = $1 AND org_id = $2",
            member,
            &auth.org_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        if known.is_none() {
            return Err(ScimError::bad(
                "invalidValue",
                format!("unknown member {member}"),
            ));
        }
        sqlx::query!(
            "INSERT INTO scim_group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &group.id,
            member,
        )
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

fn group_from_body(body: &Value) -> ScimResult<(String, String, Vec<String>)> {
    let display_name = text(body.get("displayName").unwrap_or(&Value::Null), 200)?;
    if display_name.is_empty() {
        return Err(ScimError::bad("invalidValue", "displayName is required"));
    }
    let external_id = text(body.get("externalId").unwrap_or(&Value::Null), 255)?;
    let members = match body.get("members") {
        Some(Value::Null) | None => Vec::new(),
        Some(members) => member_ids(members)?,
    };
    Ok((display_name, external_id, members))
}

fn group_lookup<'a>(group: &'a GroupRow) -> impl Fn(&str) -> Option<Attribute> + 'a {
    move |attr| {
        let values = match attr {
            "id" => vec![group.id.clone()],
            "displayname" => vec![group.display_name.clone()],
            "externalid" => vec![group.external_id.clone()],
            "members.value" | "members" => group.members.iter().map(|(id, _)| id.clone()).collect(),
            _ => return None,
        };
        let values: Vec<FilterValue> = values
            .into_iter()
            .filter(|v| !v.is_empty())
            .map(FilterValue::Str)
            .collect();
        (!values.is_empty()).then_some(Attribute {
            values,
            case_exact: attr != "displayname",
        })
    }
}

pub async fn list_groups(
    State(state): State<AppState>,
    auth: ScimAuth,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    let filter = parsed_filter(&query)?;
    let mut conn = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
    let groups: Vec<GroupRow> = load_groups(&mut conn, &auth.org_id, None)
        .await?
        .into_iter()
        .filter(|g| {
            filter
                .as_ref()
                .is_none_or(|f| filter::matches(f, &group_lookup(g)))
        })
        .collect();
    let (total, start, groups) = page(groups, &query);
    let base = base_url(&state);
    Ok(list_response(
        total,
        start,
        groups.iter().map(|g| group_json(&base, g)).collect(),
    ))
}

async fn load_group(state: &AppState, org_id: &str, id: &str) -> ScimResult<GroupRow> {
    let mut conn = state.db.as_org(OrgCredential::Scim, org_id).await?;
    load_groups(&mut conn, org_id, Some(id))
        .await?
        .into_iter()
        .next()
        .ok_or_else(ScimError::not_found)
}

pub async fn get_group(
    State(state): State<AppState>,
    auth: ScimAuth,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    let group = load_group(&state, &auth.org_id, &id).await?;
    Ok(scim_json(
        StatusCode::OK,
        group_json(&base_url(&state), &group),
    ))
}

pub async fn create_group(
    State(state): State<AppState>,
    auth: ScimAuth,
    body: Bytes,
) -> ScimResult<Response> {
    let (display_name, external_id, members) = group_from_body(&parse_body(&body)?)?;
    let now = now_ms();
    let group = GroupRow {
        id: new_id()?,
        external_id,
        display_name,
        members: Vec::new(),
        version: 1,
        created_at: now,
        updated_at: now,
    };
    save_group(&state, &auth, &group, &members, true).await?;
    let group = load_group(&state, &auth.org_id, &group.id).await?;
    let base = base_url(&state);
    let mut response = scim_json(StatusCode::CREATED, group_json(&base, &group));
    if let Ok(location) = HeaderValue::from_str(&format!("{base}/Groups/{}", group.id)) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}

pub async fn replace_group(
    State(state): State<AppState>,
    auth: ScimAuth,
    Path(id): Path<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let (display_name, external_id, members) = group_from_body(&parse_body(&body)?)?;
    let mut group = load_group(&state, &auth.org_id, &id).await?;
    group.display_name = display_name;
    group.external_id = external_id;
    group.version += 1;
    group.updated_at = now_ms();
    save_group(&state, &auth, &group, &members, false).await?;
    let group = load_group(&state, &auth.org_id, &id).await?;
    Ok(scim_json(
        StatusCode::OK,
        group_json(&base_url(&state), &group),
    ))
}

pub async fn patch_group(
    State(state): State<AppState>,
    auth: ScimAuth,
    Path(id): Path<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let ops = operations(&parse_body(&body)?)?;
    let mut group = load_group(&state, &auth.org_id, &id).await?;
    let mut members: Vec<String> = group.members.iter().map(|(id, _)| id.clone()).collect();
    let add = |members: &mut Vec<String>, ids: Vec<String>| {
        for id in ids {
            if !members.contains(&id) {
                members.push(id);
            }
        }
    };
    for (op, path, value) in ops {
        let target = path.as_deref().map(filter::normalize);
        match (op.as_str(), target.as_deref()) {
            ("remove", Some(t)) if t.starts_with("members") => {
                let path = path.as_deref().unwrap_or_default();
                if let Some(member) = member_filter_id(path) {
                    members.retain(|m| *m != member);
                } else if value.is_null() {
                    members.clear();
                } else {
                    let remove = member_ids(&value)?;
                    members.retain(|m| !remove.contains(m));
                }
            }
            ("remove", Some("externalid")) => group.external_id.clear(),
            ("remove", _) => {}
            ("add", Some("members")) => add(&mut members, member_ids(&value)?),
            ("replace", Some("members")) => {
                members.clear();
                add(&mut members, member_ids(&value)?);
            }
            (_, Some("displayname")) => {
                group.display_name = text(&value, 200)?;
            }
            (_, Some("externalid")) => group.external_id = text(&value, 255)?,
            (_, Some(_)) => {}
            (op, None) => {
                let object = value.as_object().ok_or_else(|| {
                    ScimError::bad("invalidValue", "a value without path must be an object")
                })?;
                if let Some(name) = object.get("displayName") {
                    group.display_name = text(name, 200)?;
                }
                if let Some(external) = object.get("externalId") {
                    group.external_id = text(external, 255)?;
                }
                if let Some(list) = object.get("members") {
                    if op == "replace" {
                        members.clear();
                    }
                    add(&mut members, member_ids(list)?);
                }
            }
        }
    }
    if group.display_name.is_empty() {
        return Err(ScimError::bad("invalidValue", "displayName is required"));
    }
    group.version += 1;
    group.updated_at = now_ms();
    save_group(&state, &auth, &group, &members, false).await?;
    let group = load_group(&state, &auth.org_id, &id).await?;
    Ok(scim_json(
        StatusCode::OK,
        group_json(&base_url(&state), &group),
    ))
}

pub async fn delete_group(
    State(state): State<AppState>,
    auth: ScimAuth,
    Path(id): Path<String>,
) -> ScimResult<StatusCode> {
    let mut tx = state.db.as_org(OrgCredential::Scim, &auth.org_id).await?;
    let deleted = sqlx::query!(
        "DELETE FROM scim_groups WHERE id = $1 AND org_id = $2",
        &id,
        &auth.org_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if deleted.rows_affected() == 0 {
        return Err(ScimError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- Admin API (signed in) ------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    id: String,
    name: String,
    created_by: String,
    created_at: i64,
    expires_at: i64,
    last_used_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionedUser {
    id: String,
    user_name: String,
    email: String,
    display_name: String,
    active: bool,
    /// `invited`, `not_joined`, `pending_confirmation`, `confirmed`,
    /// `suspended` or `deactivated`.
    status: &'static str,
    /// Set once the person joined; needed to confirm them.
    account_id: Option<String>,
    groups: Vec<String>,
    updated_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionedGroup {
    id: String,
    display_name: String,
    members: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimOverview {
    /// The SCIM base URL to enter at the identity provider.
    base_url: String,
    tokens: Vec<TokenInfo>,
    users: Vec<ProvisionedUser>,
    groups: Vec<ProvisionedGroup>,
}

/// `GET /orgs/{org_id}/scim` (owners and admins).
pub async fn overview(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<ScimOverview>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    let tokens: Vec<(String, String, String, i64, i64, i64)> = sqlx::query!(
        "SELECT id, name, created_by, created_at, expires_at, last_used_at FROM scim_tokens WHERE org_id = $1 \
         ORDER BY created_at DESC",
        &org_id,
    ).map(|row| (row.id, row.name, row.created_by, row.created_at, row.expires_at, row.last_used_at))
    .fetch_all(&mut *conn)
    .await?;
    let now = now_ms();
    let users = load_users(&mut conn, &org_id)
        .await
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("loading SCIM users")))?;
    let mut provisioned = Vec::with_capacity(users.len());
    for user in users {
        let member: Option<(String, String)> = sqlx::query!(
            "SELECT org_members.account_id, org_members.status FROM org_members \
             JOIN account_directory accounts ON accounts.id = org_members.account_id \
             WHERE org_members.org_id = $1 AND accounts.email = $2",
            &org_id,
            &user.attrs.email,
        )
        .map(|row| (row.account_id, row.status))
        .fetch_optional(&mut *conn)
        .await?;
        let invited: Option<i64> = sqlx::query_scalar!(
            "SELECT 1::BIGINT AS \"one!\" FROM org_invitations WHERE org_id = $1 AND email = $2 AND status = 'pending' AND expires_at > $3",
            &org_id,
            &user.attrs.email,
            now,
        )
        .fetch_optional(&mut *conn)
        .await?;
        let status = match (&member, user.attrs.active) {
            (_, false) => "deactivated",
            (Some((_, s)), true) if s == "accepted" => "pending_confirmation",
            (Some((_, s)), true) if s == "confirmed" => "confirmed",
            (Some(_), true) => "suspended",
            (None, true) if invited.is_some() => "invited",
            (None, true) => "not_joined",
        };
        let groups = user_groups(&mut conn, &user.id)
            .await
            .map_err(|_| ApiError::Internal(anyhow::anyhow!("loading SCIM groups")))?
            .into_iter()
            .map(|(_, name)| name)
            .collect();
        provisioned.push(ProvisionedUser {
            id: user.id,
            user_name: user.attrs.user_name,
            email: user.attrs.email,
            display_name: user.attrs.display_name,
            active: user.attrs.active,
            status,
            account_id: member.map(|(account_id, _)| account_id),
            groups,
            updated_at: user.updated_at,
        });
    }
    let groups: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT scim_groups.id, scim_groups.display_name, COUNT(scim_group_members.user_id) FROM scim_groups \
         LEFT JOIN scim_group_members ON scim_group_members.group_id = scim_groups.id \
         WHERE scim_groups.org_id = $1 GROUP BY scim_groups.id, scim_groups.display_name ORDER BY scim_groups.display_name",
    )
    .bind(&org_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(ScimOverview {
        base_url: base_url(&state),
        tokens: tokens
            .into_iter()
            .map(
                |(id, name, created_by, created_at, expires_at, last_used_at)| TokenInfo {
                    id,
                    name,
                    created_by,
                    created_at,
                    expires_at,
                    last_used_at,
                },
            )
            .collect(),
        users: provisioned,
        groups: groups
            .into_iter()
            .map(|(id, display_name, members)| ProvisionedGroup {
                id,
                display_name,
                members: usize::try_from(members).unwrap_or(0),
            })
            .collect(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTokenRequest {
    name: String,
    /// 1 to 730 days (default 365).
    #[serde(default)]
    expires_in_days: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedToken {
    id: String,
    /// Shown once; only its hash is stored.
    token: String,
    expires_at: i64,
    base_url: String,
}

/// `POST /orgs/{org_id}/scim/tokens` (owners and admins, recent login).
pub async fn create_token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<CreateTokenRequest>,
) -> ApiResult<(StatusCode, Json<CreatedToken>)> {
    validate::id("organization id", &org_id)?;
    super::account::require_recent_login(&session)?;
    let name: String = req
        .name
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect::<String>()
        .trim()
        .to_owned();
    if name.is_empty() {
        return Err(ApiError::bad_request(
            "name the token, for example after the identity provider",
        ));
    }
    let days = req.expires_in_days.unwrap_or(365);
    if !(1..=730).contains(&days) {
        return Err(ApiError::bad_request(
            "expiresInDays must be between 1 and 730",
        ));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let kind: String =
        sqlx::query_scalar!("SELECT kind FROM organizations WHERE id = $1", &org_id,)
            .fetch_one(&mut *tx)
            .await?;
    if kind != "team" {
        return Err(ApiError::forbidden(
            "scim_team_only",
            "provisioning is available for team organizations",
        ));
    }
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM scim_tokens WHERE org_id = $1",
        &org_id,
    )
    .fetch_one(&mut *tx)
    .await?;
    if count >= MAX_TOKENS {
        return Err(ApiError::bad_request("revoke a token first (at most 10)"));
    }
    let id = new_id()?;
    let token = format!(
        "pbx_scim_{}",
        encoding::encode(
            &passbox_core::random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?
        )
    );
    let now = now_ms();
    let expires_at = now + days * 24 * 60 * 60 * 1000;
    sqlx::query!(
        "INSERT INTO scim_tokens (id, org_id, name, token_hash, created_by, created_at, expires_at, last_used_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 0)",
        &id,
        &org_id,
        &name,
        hash(&token),
        &session.account_id,
        now,
        expires_at,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "org_scim_token_created",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedToken {
            id,
            token,
            expires_at,
            base_url: base_url(&state),
        }),
    ))
}

/// `DELETE /orgs/{org_id}/scim/tokens/{id}` (owners and admins).
pub async fn revoke_token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::id("token id", &id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let deleted = sqlx::query!(
        "DELETE FROM scim_tokens WHERE id = $1 AND org_id = $2",
        &id,
        &org_id,
    )
    .execute(&mut *tx)
    .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "org_scim_token_revoked",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_times() {
        assert_eq!(iso_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_time(1_700_000_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso_time(951_782_400_000), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn parses_users_and_patches() {
        let attrs = user_attrs(&json!({
            "schemas": [USER_SCHEMA], "userName": "Ada@Acme.example", "externalId": "00u1",
            "name": { "givenName": "Ada", "familyName": "Lovelace" },
            "emails": [{ "value": "a@x.example", "primary": false }, { "value": "ada@acme.example", "primary": true }],
            "title": "ignored",
        }))
        .unwrap();
        assert_eq!(attrs.email, "ada@acme.example");
        assert!(attrs.active);
        assert_eq!(attrs.given_name, "Ada");
        let mut patched = attrs.clone();
        set_user_attr(&mut patched, "active", &json!("False")).unwrap();
        set_user_attr(
            &mut patched,
            r#"emails[type eq "work"].value"#,
            &json!("NEW@acme.example"),
        )
        .unwrap();
        set_user_attr(
            &mut patched,
            "urn:ietf:params:scim:schemas:core:2.0:User:name.familyName",
            &json!("King"),
        )
        .unwrap();
        finish_user(&mut patched).unwrap();
        assert!(!patched.active);
        assert_eq!(patched.email, "new@acme.example");
        assert_eq!(patched.family_name, "King");
        assert!(user_attrs(&json!({ "userName": "no-email" })).is_err());
        assert!(user_attrs(&json!({ "emails": [{ "value": "a@b.example" }] })).is_err());
        assert!(set_user_attr(&mut patched, "active", &json!(3)).is_err());
        assert_eq!(
            member_filter_id(r#"members[value eq "abc"]"#).as_deref(),
            Some("abc")
        );
        assert_eq!(member_filter_id("members"), None);
    }
}
