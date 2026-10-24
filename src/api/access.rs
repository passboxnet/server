//! Authorization for organizations and shared vaults.
//!
//! The server enforces roles on every request (members only see their
//! organizations, only admins manage them, only vault managers change
//! members, view-only members cannot write). Clients verify the same rules
//! cryptographically (signed attestations and manifests), so a server that
//! skipped these checks could not grant access to keys, only to ciphertext.

use passbox_core::sharing::objects::{OrgRole, VaultRole};
use sqlx::AnyConnection;

use crate::error::{ApiError, ApiResult};

/// A member's role and status in an organization.
#[derive(Debug, Clone)]
pub struct Membership {
    pub role: OrgRole,
    pub status: String,
}

impl Membership {
    pub fn is_confirmed(&self) -> bool {
        self.status == "confirmed"
    }

    pub fn is_admin(&self) -> bool {
        self.is_confirmed() && self.role.is_admin()
    }
}

pub async fn membership(
    conn: &mut AnyConnection,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Option<Membership>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT role, status FROM org_members WHERE org_id = $1 AND account_id = $2",
    )
    .bind(org_id)
    .bind(account_id)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(|(role, status)| {
        Ok(Membership {
            role: OrgRole::parse(&role).map_err(|e| ApiError::Internal(e.into()))?,
            status,
        })
    })
    .transpose()
}

/// Any membership (including accepted and suspended); 404 otherwise, so
/// non-members cannot tell whether an organization exists.
pub async fn require_member(
    conn: &mut AnyConnection,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Membership> {
    membership(conn, org_id, account_id)
        .await?
        .ok_or(ApiError::NotFound)
}

pub async fn require_confirmed(
    conn: &mut AnyConnection,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Membership> {
    let m = require_member(conn, org_id, account_id).await?;
    if !m.is_confirmed() {
        return Err(ApiError::forbidden("your membership is not confirmed"));
    }
    Ok(m)
}

pub async fn require_admin(
    conn: &mut AnyConnection,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Membership> {
    let m = require_member(conn, org_id, account_id).await?;
    if !m.is_admin() {
        return Err(ApiError::forbidden(
            "only owners and admins of the organization can do this",
        ));
    }
    Ok(m)
}

/// How an account may use a vault.
#[derive(Debug, Clone)]
pub enum VaultAccess {
    /// The account's own personal vault.
    Personal,
    Shared {
        org_id: String,
        role: VaultRole,
        key_epoch: i64,
    },
}

impl VaultAccess {
    pub fn can_write(&self) -> bool {
        match self {
            Self::Personal => true,
            Self::Shared { role, .. } => role.can_write(),
        }
    }
}

/// The account's role in a shared vault via direct membership or groups,
/// if it is a confirmed member of the vault's organization.
pub async fn shared_role(
    conn: &mut AnyConnection,
    vault_id: &str,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Option<VaultRole>> {
    match membership(conn, org_id, account_id).await? {
        Some(m) if m.is_confirmed() => {}
        _ => return Ok(None),
    }
    let direct: Vec<String> = sqlx::query_scalar(
        "SELECT role FROM vault_members WHERE vault_id = $1 AND principal_type = 'account' \
         AND principal_id = $2",
    )
    .bind(vault_id)
    .bind(account_id)
    .fetch_all(&mut *conn)
    .await?;
    let via_groups: Vec<String> = sqlx::query_scalar(
        "SELECT vault_members.role FROM vault_members \
         JOIN org_groups ON org_groups.id = vault_members.principal_id \
         JOIN group_members ON group_members.group_id = org_groups.id \
           AND group_members.key_version = org_groups.key_version \
         WHERE vault_members.vault_id = $1 AND vault_members.principal_type = 'group' \
           AND group_members.account_id = $2",
    )
    .bind(vault_id)
    .bind(account_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(direct
        .iter()
        .chain(via_groups.iter())
        .filter_map(|r| VaultRole::parse(r).ok())
        .max())
}

/// The account's access to a vault; `None` if it has none (callers answer
/// 404 so vault IDs of others are not revealed).
pub async fn vault_access(
    conn: &mut AnyConnection,
    vault_id: &str,
    account_id: &str,
) -> ApiResult<Option<VaultAccess>> {
    let row: Option<(String, Option<String>, i64)> =
        sqlx::query_as("SELECT account_id, org_id, key_epoch FROM vaults WHERE id = $1")
            .bind(vault_id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((owner, org_id, key_epoch)) = row else {
        return Ok(None);
    };
    match org_id {
        None => Ok((owner == account_id).then_some(VaultAccess::Personal)),
        Some(org_id) => Ok(shared_role(conn, vault_id, &org_id, account_id)
            .await?
            .map(|role| VaultAccess::Shared {
                org_id,
                role,
                key_epoch,
            })),
    }
}

/// Requires write access (personal vault, or `edit`/`manage`). A member
/// with `view` gets 403.
pub async fn require_vault_write(
    conn: &mut AnyConnection,
    vault_id: &str,
    account_id: &str,
) -> ApiResult<VaultAccess> {
    let access = vault_access(conn, vault_id, account_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !access.can_write() {
        return Err(ApiError::forbidden("you can only view this vault"));
    }
    Ok(access)
}

pub async fn require_vault_manager(
    conn: &mut AnyConnection,
    vault_id: &str,
    account_id: &str,
) -> ApiResult<(String, i64)> {
    match vault_access(conn, vault_id, account_id).await? {
        Some(VaultAccess::Shared {
            org_id,
            role,
            key_epoch,
        }) => {
            // Organization admins who are members of the vault may manage it
            // too (clients accept their signatures as anchors).
            let admin = membership(conn, &org_id, account_id)
                .await?
                .is_some_and(|m| m.is_admin());
            if role.can_manage() || admin {
                Ok((org_id, key_epoch))
            } else {
                Err(ApiError::forbidden(
                    "only managers of the vault can do this",
                ))
            }
        }
        Some(VaultAccess::Personal) => Err(ApiError::bad_request(
            "personal vaults cannot be shared; create a shared vault in an organization",
        )),
        None => Err(ApiError::NotFound),
    }
}
