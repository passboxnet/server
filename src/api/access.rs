//! Authorization for organizations and shared vaults.
//!
//! The server enforces roles on every request (members only see their
//! organizations, only admins manage them, only vault managers change
//! members, view-only members cannot write). Clients verify the same rules
//! cryptographically (signed attestations and manifests), so a server that
//! skipped these checks could not grant access to keys, only to ciphertext.

use passbox_core::sharing::objects::{OrgRole, VaultRole};
use sqlx::PgConnection;

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
    conn: &mut PgConnection,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Option<Membership>> {
    let row: Option<(String, String)> = sqlx::query!(
        "SELECT role, status FROM org_members WHERE org_id = $1 AND account_id = $2",
        org_id,
        account_id,
    )
    .map(|row| (row.role, row.status))
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
    conn: &mut PgConnection,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Membership> {
    membership(conn, org_id, account_id)
        .await?
        .ok_or(ApiError::NotFound)
}

pub async fn require_confirmed(
    conn: &mut PgConnection,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Membership> {
    let m = require_member(conn, org_id, account_id).await?;
    if !m.is_confirmed() {
        return Err(ApiError::forbidden(
            "forbidden",
            "your membership is not confirmed",
        ));
    }
    Ok(m)
}

pub async fn require_admin(
    conn: &mut PgConnection,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Membership> {
    let m = require_member(conn, org_id, account_id).await?;
    if !m.is_admin() {
        return Err(ApiError::forbidden(
            "forbidden",
            "only owners and admins of the organization can do this",
        ));
    }
    Ok(m)
}

/// Whether the organization is a family, as far as the current context
/// can see it (members, the organization's SCIM, SSO and events
/// contexts). Policies, the activity log, single sign-on and provisioning
/// are features of team organizations (Business); families do without
/// them on every instance.
pub async fn is_family(conn: &mut PgConnection, org_id: &str) -> ApiResult<bool> {
    let kind: Option<String> =
        sqlx::query_scalar!("SELECT kind FROM organizations WHERE id = $1", org_id)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(kind.as_deref() == Some("family"))
}

/// 403 `code` for a family organization: the feature is for teams.
pub async fn require_team(
    conn: &mut PgConnection,
    org_id: &str,
    code: &'static str,
    message: &'static str,
) -> ApiResult<()> {
    if is_family(conn, org_id).await? {
        return Err(ApiError::forbidden(code, message));
    }
    Ok(())
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

/// Error code for anything a guest tries beyond viewing (guests are view-only).
pub const GUEST_VIEW_ONLY: &str = "guest_view_only";

/// The 403 a guest gets for creating or changing anything.
pub fn guest_view_only() -> ApiError {
    ApiError::forbidden(
        GUEST_VIEW_ONLY,
        "guests can only view, copy and fill items of the vaults shared with them; \
         ask an admin of the organization to make you a member",
    )
}

/// Whether the account is a guest of the organization.
pub async fn is_guest(conn: &mut PgConnection, org_id: &str, account_id: &str) -> ApiResult<bool> {
    Ok(membership(conn, org_id, account_id)
        .await?
        .is_some_and(|m| m.role == OrgRole::Guest))
}

/// The account's role in a shared vault via direct membership or groups,
/// if it is a confirmed member of the vault's organization. Guests are
/// view-only: their role is capped at `view` whatever the manifest says.
pub async fn shared_role(
    conn: &mut PgConnection,
    vault_id: &str,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Option<VaultRole>> {
    let guest = match membership(conn, org_id, account_id).await? {
        Some(m) if m.is_confirmed() => m.role == OrgRole::Guest,
        _ => return Ok(None),
    };
    let direct: Vec<String> = sqlx::query_scalar!(
        "SELECT role FROM vault_members WHERE vault_id = $1 AND principal_type = 'account' \
         AND principal_id = $2",
        vault_id,
        account_id,
    )
    .fetch_all(&mut *conn)
    .await?;
    let via_groups: Vec<String> = sqlx::query_scalar!(
        "SELECT vault_members.role FROM vault_members \
         JOIN org_groups ON org_groups.id = vault_members.principal_id \
         JOIN group_members ON group_members.group_id = org_groups.id \
           AND group_members.key_version = org_groups.key_version \
         WHERE vault_members.vault_id = $1 AND vault_members.principal_type = 'group' \
           AND group_members.account_id = $2",
        vault_id,
        account_id,
    )
    .fetch_all(&mut *conn)
    .await?;
    let role = direct
        .iter()
        .chain(via_groups.iter())
        .filter_map(|r| VaultRole::parse(r).ok())
        .max();
    Ok(if guest {
        role.map(|r| r.min(VaultRole::View))
    } else {
        role
    })
}

/// The account's access to a vault; `None` if it has none (callers answer
/// 404 so vault IDs of others are not revealed).
pub async fn vault_access(
    conn: &mut PgConnection,
    vault_id: &str,
    account_id: &str,
) -> ApiResult<Option<VaultAccess>> {
    let row: Option<(String, Option<String>, i64)> = sqlx::query!(
        "SELECT account_id, org_id, key_epoch FROM vaults WHERE id = $1",
        vault_id,
    )
    .map(|row| (row.account_id, row.org_id, row.key_epoch))
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

/// The organization's lock, if it is read-only (`crate::ext`).
pub async fn org_lock(
    conn: &mut PgConnection,
    org_id: &str,
) -> ApiResult<Option<crate::ext::OrgLock>> {
    Ok(sqlx::query_as!(
        crate::ext::OrgLock,
        "SELECT reason, source FROM org_locks WHERE org_id = $1",
        org_id,
    )
    .fetch_optional(&mut *conn)
    .await?)
}

/// 403 `org_read_only` while the organization is locked. Reading, syncing,
/// exporting, removing and suspending members and deleting the
/// organization stay possible; creating and changing things does not.
pub async fn require_unlocked(conn: &mut PgConnection, org_id: &str) -> ApiResult<()> {
    match org_lock(conn, org_id).await? {
        Some(lock) => Err(crate::ext::read_only(&lock)),
        None => Ok(()),
    }
}

/// Requires write access (personal vault, or `edit`/`manage`). A member
/// with `view` gets 403, and so does everyone while the vault's
/// organization is read-only.
pub async fn require_vault_write(
    conn: &mut PgConnection,
    vault_id: &str,
    account_id: &str,
) -> ApiResult<VaultAccess> {
    let access = vault_access(conn, vault_id, account_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !access.can_write() {
        if let VaultAccess::Shared { org_id, .. } = &access
            && is_guest(conn, org_id, account_id).await?
        {
            return Err(guest_view_only());
        }
        return Err(ApiError::forbidden(
            "forbidden",
            "you can only view this vault",
        ));
    }
    if let VaultAccess::Shared { org_id, .. } = &access {
        require_unlocked(conn, org_id).await?;
    }
    Ok(access)
}

/// Requires the right to manage a shared vault (members, keys), and an
/// organization that is not read-only. Returns the organization and the
/// vault's key epoch.
pub async fn require_vault_manager(
    conn: &mut PgConnection,
    vault_id: &str,
    account_id: &str,
) -> ApiResult<(String, i64)> {
    let (org_id, key_epoch) = vault_manager(conn, vault_id, account_id).await?;
    require_unlocked(conn, &org_id).await?;
    Ok((org_id, key_epoch))
}

/// Like [`require_vault_manager`], also while the organization is
/// read-only: for rotating keys after a member left and for checks that
/// change nothing.
pub async fn vault_manager(
    conn: &mut PgConnection,
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
                    "forbidden",
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
