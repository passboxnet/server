//! Server-side checks of uploaded signed objects.
//!
//! Clients verify everything themselves; these checks keep obviously wrong
//! or forged uploads out of the database and give clear errors. The server
//! checks that objects parse, name the right IDs, and are signed by the
//! uploading account's published key.

use passbox_core::identity::SignedBundle;
use passbox_core::sharing::objects::{Canonical, Signed};
use sqlx::AnyConnection;

use super::validate;
use crate::error::{ApiError, ApiResult};

/// The latest published bundle of an account.
pub async fn bundle(conn: &mut AnyConnection, account_id: &str) -> ApiResult<Option<SignedBundle>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT bundle, bundle_signature FROM account_keys WHERE account_id = $1 \
         ORDER BY key_version DESC LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|(b, s)| {
        SignedBundle::parse(&b, &s).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))
    })
    .transpose()
}

/// The uploader's bundle; 400 if the account has not published keys yet.
pub async fn own_bundle(conn: &mut AnyConnection, account_id: &str) -> ApiResult<SignedBundle> {
    bundle(conn, account_id)
        .await?
        .ok_or_else(|| ApiError::bad_request("publish your account keys first"))
}

/// Parses a signed object and checks the signature against `signer`.
pub fn parse<T: Canonical>(
    field: &str,
    object: &str,
    signature: &str,
    signer: &SignedBundle,
) -> ApiResult<Signed<T>> {
    validate::base64(field, object, validate::MAX_SMALL_LEN * 8)?;
    validate::base64(&format!("{field}Signature"), signature, 256)?;
    let signed = Signed::<T>::parse(object, signature)
        .map_err(|e| ApiError::bad_request(format!("invalid {field}: {e}")))?;
    signed
        .verify(&signer.bundle.sig_pk)
        .map_err(|_| ApiError::bad_request(format!("{field} is not signed by your key")))?;
    Ok(signed)
}

pub fn sealed(field: &str, value: &str) -> ApiResult<Vec<u8>> {
    validate::base64(field, value, validate::MAX_SMALL_LEN)
}

pub fn bad(message: &str) -> ApiError {
    ApiError::bad_request(message)
}
