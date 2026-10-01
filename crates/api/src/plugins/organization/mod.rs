pub mod handlers;
pub mod rbac;
pub mod types;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::entity::AuthSession;
use better_auth_core::error::AuthResult;
use better_auth_core::plugin::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::types::{AuthRequest, AuthResponse, HttpMethod};

/// Data supplied when an invitation is created or resent.
pub struct InvitationEmail {
    /// The persisted invitation, including its current expiration.
    pub invitation: better_auth_core::wire::InvitationView,
    /// The organization receiving the invited member.
    pub organization: better_auth_core::wire::OrganizationView,
    /// The member sending the invitation.
    pub member: better_auth_core::types::Member,
    /// The user sending the invitation.
    pub inviter: better_auth_core::wire::UserView,
}

/// Application callback for invitation email delivery.
#[async_trait]
pub trait SendInvitationEmail: Send + Sync {
    /// Send the invitation email. The plugin logs delivery errors without failing the request.
    async fn send(&self, email: &InvitationEmail) -> AuthResult<()>;
}

/// Permission definitions for a role
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RolePermissions {
    pub organization: Vec<String>,
    pub member: Vec<String>,
    pub invitation: Vec<String>,
    /// Actions this role may perform on organization-owned API keys. Upstream's
    /// default statements define none, so only the creator role can manage them
    /// until an application grants this explicitly.
    pub api_key: Vec<String>,
}

/// Configuration for the Organization plugin
#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "OrganizationPlugin")]
pub struct OrganizationConfig {
    /// Allow users to create organizations (default: true)
    #[config(default = true)]
    pub allow_user_to_create_organization: bool,
    /// Maximum organizations per user (None = unlimited)
    #[config(default = None)]
    pub organization_limit: Option<usize>,
    /// Maximum members per organization (None = unlimited)
    #[config(default = Some(100))]
    pub membership_limit: Option<usize>,
    /// Role assigned to organization creator (default: "owner")
    #[config(default = "owner".to_string())]
    pub creator_role: String,
    /// Invitation expiration in seconds (default: 48 hours)
    #[config(default = 60 * 60 * 48)]
    pub invitation_expires_in: u64,
    /// Maximum pending invitations per organization (None = unlimited)
    #[config(default = Some(100))]
    pub invitation_limit: Option<usize>,
    /// Disable organization deletion (default: false)
    #[config(default = false)]
    pub disable_organization_deletion: bool,
    /// Custom role definitions (extending default roles)
    #[config(default = HashMap::new(), skip)]
    pub roles: HashMap<String, RolePermissions>,
    /// Optional delivery callback used for new and resent invitations.
    #[config(default = None, skip)]
    pub send_invitation_email: Option<Arc<dyn SendInvitationEmail>>,
}

impl std::fmt::Debug for OrganizationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganizationConfig")
            .field(
                "allow_user_to_create_organization",
                &self.allow_user_to_create_organization,
            )
            .field("organization_limit", &self.organization_limit)
            .field("membership_limit", &self.membership_limit)
            .field("creator_role", &self.creator_role)
            .field("invitation_expires_in", &self.invitation_expires_in)
            .field("invitation_limit", &self.invitation_limit)
            .field(
                "disable_organization_deletion",
                &self.disable_organization_deletion,
            )
            .field("roles", &self.roles)
            .field(
                "send_invitation_email",
                &self.send_invitation_email.as_ref().map(|_| "custom"),
            )
            .finish()
    }
}

/// Organization plugin for multi-tenancy support
pub struct OrganizationPlugin {
    config: OrganizationConfig,
}

impl OrganizationPlugin {
    /// Configure delivery for new and resent invitations.
    pub fn custom_send_invitation_email(mut self, sender: Arc<dyn SendInvitationEmail>) -> Self {
        self.config.send_invitation_email = Some(sender);
        self
    }
}

/// Metadata key announcing that the organization plugin is installed.
pub(crate) const METADATA_ENABLED: &str = "organization.enabled";
/// Metadata key carrying the configured custom roles, so other plugins can run
/// the organization's access control without depending on this plugin's config.
pub(crate) const METADATA_ROLES: &str = "organization.roles";
/// Metadata key carrying the creator role, which is allowed every action.
pub(crate) const METADATA_CREATOR_ROLE: &str = "organization.creator_role";

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for OrganizationPlugin {
    fn name(&self) -> &'static str {
        "organization"
    }

    async fn on_init(
        &self,
        ctx: &mut better_auth_core::AuthInitContext<S>,
    ) -> better_auth_core::AuthResult<()> {
        S::Session::require_plugin_fields("organization", &["active_organization_id"])?;
        ctx.set_metadata(METADATA_ENABLED, serde_json::Value::Bool(true));
        ctx.set_metadata(
            METADATA_ROLES,
            serde_json::to_value(&self.config.roles).unwrap_or_default(),
        );
        ctx.set_metadata(
            METADATA_CREATOR_ROLE,
            serde_json::Value::String(self.config.creator_role.clone()),
        );
        Ok(())
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            // Organization CRUD
            AuthRoute::post("/organization/create", "create_organization"),
            AuthRoute::post("/organization/update", "update_organization"),
            AuthRoute::post("/organization/delete", "delete_organization"),
            AuthRoute::get("/organization/list", "list_organizations"),
            AuthRoute::get("/organization/get-organization", "get_organization"),
            AuthRoute::get(
                "/organization/get-full-organization",
                "get_full_organization",
            ),
            AuthRoute::post("/organization/check-slug", "check_slug"),
            AuthRoute::post("/organization/set-active", "set_active_organization"),
            AuthRoute::post("/organization/leave", "leave_organization"),
            // Member management
            AuthRoute::get("/organization/get-active-member", "get_active_member"),
            AuthRoute::get(
                "/organization/get-active-member-role",
                "get_active_member_role",
            ),
            AuthRoute::get("/organization/list-members", "list_members"),
            AuthRoute::post("/organization/remove-member", "remove_member"),
            AuthRoute::post("/organization/update-member-role", "update_member_role"),
            // Invitations
            AuthRoute::post("/organization/invite-member", "invite_member"),
            AuthRoute::get("/organization/get-invitation", "get_invitation"),
            AuthRoute::get("/organization/list-invitations", "list_invitations"),
            AuthRoute::get(
                "/organization/list-user-invitations",
                "list_user_invitations",
            ),
            AuthRoute::post("/organization/accept-invitation", "accept_invitation"),
            AuthRoute::post("/organization/reject-invitation", "reject_invitation"),
            AuthRoute::post("/organization/cancel-invitation", "cancel_invitation"),
            // Permission check
            AuthRoute::post("/organization/has-permission", "has_permission"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            // Organization CRUD
            (HttpMethod::Post, "/organization/create") => Ok(Some(
                handlers::org::handle_create_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/update") => Ok(Some(
                handlers::org::handle_update_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/delete") => Ok(Some(
                handlers::org::handle_delete_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Get, "/organization/list") => Ok(Some(
                handlers::org::handle_list_organizations(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/get-organization") => Ok(Some(
                handlers::org::handle_get_organization(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/get-full-organization") => Ok(Some(
                handlers::org::handle_get_full_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/check-slug") => {
                Ok(Some(handlers::org::handle_check_slug(req, ctx).await?))
            }
            (HttpMethod::Post, "/organization/set-active") => Ok(Some(
                handlers::org::handle_set_active_organization(req, ctx).await?,
            )),
            (HttpMethod::Post, "/organization/leave") => Ok(Some(
                handlers::org::handle_leave_organization(req, ctx, &self.config).await?,
            )),
            // Member management
            (HttpMethod::Get, "/organization/get-active-member") => Ok(Some(
                handlers::member::handle_get_active_member(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/get-active-member-role") => Ok(Some(
                handlers::member::handle_get_active_member_role(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/list-members") => {
                Ok(Some(handlers::member::handle_list_members(req, ctx).await?))
            }
            (HttpMethod::Post, "/organization/remove-member") => Ok(Some(
                handlers::member::handle_remove_member(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/update-member-role") => Ok(Some(
                handlers::member::handle_update_member_role(req, ctx, &self.config).await?,
            )),
            // Invitations
            (HttpMethod::Post, "/organization/invite-member") => Ok(Some(
                handlers::invitation::handle_invite_member(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Get, "/organization/get-invitation") => Ok(Some(
                handlers::invitation::handle_get_invitation(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/list-invitations") => Ok(Some(
                handlers::invitation::handle_list_invitations(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/list-user-invitations") => Ok(Some(
                handlers::invitation::handle_list_user_invitations(req, ctx).await?,
            )),
            (HttpMethod::Post, "/organization/accept-invitation") => Ok(Some(
                handlers::invitation::handle_accept_invitation(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/reject-invitation") => Ok(Some(
                handlers::invitation::handle_reject_invitation(req, ctx).await?,
            )),
            (HttpMethod::Post, "/organization/cancel-invitation") => Ok(Some(
                handlers::invitation::handle_cancel_invitation(req, ctx, &self.config).await?,
            )),
            // Permission check
            (HttpMethod::Post, "/organization/has-permission") => Ok(Some(
                handlers::handle_has_permission(req, ctx, &self.config).await?,
            )),
            _ => Ok(None),
        }
    }
}
