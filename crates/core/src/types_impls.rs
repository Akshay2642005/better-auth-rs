use chrono::{DateTime, Utc};

use crate::entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification,
};
use crate::store::sea_orm::entities;

use super::types::{Account, ApiKey, Passkey, Session, TwoFactor, User, Verification};
use super::types_org::{Invitation, InvitationStatus, Member, Organization};

fn to_rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

/// Blanket conversion from any [`AuthUser`] implementor to the concrete [`User`] type.
///
/// This avoids hand-written `to_user()` helpers scattered across plugins.
impl<T: AuthUser> From<&T> for User {
    fn from(u: &T) -> Self {
        Self {
            id: u.id().to_owned(),
            name: u.name().map(str::to_owned),
            email: u.email().map(str::to_owned),
            email_verified: u.email_verified(),
            image: u.image().map(str::to_owned),
            created_at: u.created_at(),
            updated_at: u.updated_at(),
            username: u.username().map(str::to_owned),
            display_username: u.display_username().map(str::to_owned),
            two_factor_enabled: u.two_factor_enabled(),
            role: u.role().map(str::to_owned),
            banned: u.banned(),
            ban_reason: u.ban_reason().map(str::to_owned),
            ban_expires: u.ban_expires(),
            metadata: u.metadata().clone(),
        }
    }
}

impl AuthUser for User {
    fn id(&self) -> &str {
        &self.id
    }
    fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn email_verified(&self) -> bool {
        self.email_verified
    }
    fn image(&self) -> Option<&str> {
        self.image.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    fn display_username(&self) -> Option<&str> {
        self.display_username.as_deref()
    }
    fn two_factor_enabled(&self) -> bool {
        self.two_factor_enabled
    }
    fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }
    fn banned(&self) -> bool {
        self.banned
    }
    fn ban_reason(&self) -> Option<&str> {
        self.ban_reason.as_deref()
    }
    fn ban_expires(&self) -> Option<DateTime<Utc>> {
        self.ban_expires
    }
    fn metadata(&self) -> &serde_json::Value {
        &self.metadata
    }
}

/// Blanket conversion from any [`AuthSession`] implementor to the concrete [`Session`] type.
impl<T: AuthSession> From<&T> for Session {
    fn from(session: &T) -> Self {
        Self {
            id: session.id().to_owned(),
            expires_at: session.expires_at(),
            token: session.token().to_owned(),
            created_at: session.created_at(),
            updated_at: session.updated_at(),
            ip_address: session.ip_address().map(str::to_owned),
            user_agent: session.user_agent().map(str::to_owned),
            user_id: session.user_id().to_owned(),
            impersonated_by: session.impersonated_by().map(str::to_owned),
            active_organization_id: session.active_organization_id().map(str::to_owned),
            active: session.active(),
        }
    }
}

impl AuthSession for Session {
    fn id(&self) -> &str {
        &self.id
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn token(&self) -> &str {
        &self.token
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    fn ip_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }
    fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn impersonated_by(&self) -> Option<&str> {
        self.impersonated_by.as_deref()
    }
    fn active_organization_id(&self) -> Option<&str> {
        self.active_organization_id.as_deref()
    }
    fn active(&self) -> bool {
        self.active
    }
}

/// Blanket conversion from any [`AuthAccount`] implementor to the concrete [`Account`] type.
impl<T: AuthAccount> From<&T> for Account {
    fn from(account: &T) -> Self {
        Self {
            id: account.id().to_owned(),
            account_id: account.account_id().to_owned(),
            provider_id: account.provider_id().to_owned(),
            user_id: account.user_id().to_owned(),
            access_token: account.access_token().map(str::to_owned),
            refresh_token: account.refresh_token().map(str::to_owned),
            id_token: account.id_token().map(str::to_owned),
            access_token_expires_at: account.access_token_expires_at(),
            refresh_token_expires_at: account.refresh_token_expires_at(),
            scope: account.scope().map(str::to_owned),
            password: account.password().map(str::to_owned),
            created_at: account.created_at(),
            updated_at: account.updated_at(),
        }
    }
}

impl AuthAccount for Account {
    fn id(&self) -> &str {
        &self.id
    }
    fn account_id(&self) -> &str {
        &self.account_id
    }
    fn provider_id(&self) -> &str {
        &self.provider_id
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }
    fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }
    fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }
    fn access_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.access_token_expires_at
    }
    fn refresh_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.refresh_token_expires_at
    }
    fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

/// Blanket conversion from any [`AuthVerification`] implementor to the concrete [`Verification`] type.
impl<T: AuthVerification> From<&T> for Verification {
    fn from(verification: &T) -> Self {
        Self {
            id: verification.id().to_owned(),
            identifier: verification.identifier().to_owned(),
            value: verification.value().to_owned(),
            expires_at: verification.expires_at(),
            created_at: verification.created_at(),
            updated_at: verification.updated_at(),
        }
    }
}

impl<T: AuthOrganization> From<&T> for Organization {
    fn from(organization: &T) -> Self {
        Self {
            id: organization.id().to_owned(),
            name: organization.name().to_owned(),
            slug: organization.slug().to_owned(),
            logo: organization.logo().map(str::to_owned),
            metadata: organization.metadata().cloned(),
            created_at: organization.created_at(),
            updated_at: organization.updated_at(),
        }
    }
}

impl From<&entities::organization::Model> for Organization {
    fn from(model: &entities::organization::Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model.name.clone(),
            slug: model.slug.clone(),
            logo: model.logo.clone(),
            metadata: Some(model.metadata.clone()),
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl AuthOrganization for Organization {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn slug(&self) -> &str {
        &self.slug
    }
    fn logo(&self) -> Option<&str> {
        self.logo.as_deref()
    }
    fn metadata(&self) -> Option<&serde_json::Value> {
        self.metadata.as_ref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl AuthMember for Member {
    fn id(&self) -> &str {
        &self.id
    }
    fn organization_id(&self) -> &str {
        &self.organization_id
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn role(&self) -> &str {
        &self.role
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl<T: AuthMember> From<&T> for Member {
    fn from(member: &T) -> Self {
        Self {
            id: member.id().to_owned(),
            organization_id: member.organization_id().to_owned(),
            user_id: member.user_id().to_owned(),
            role: member.role().to_owned(),
            created_at: member.created_at(),
        }
    }
}

impl From<&entities::member::Model> for Member {
    fn from(model: &entities::member::Model) -> Self {
        Self {
            id: model.id.clone(),
            organization_id: model.organization_id.clone(),
            user_id: model.user_id.clone(),
            role: model.role.clone(),
            created_at: model.created_at,
        }
    }
}

impl AuthInvitation for Invitation {
    fn id(&self) -> &str {
        &self.id
    }
    fn organization_id(&self) -> &str {
        &self.organization_id
    }
    fn email(&self) -> &str {
        &self.email
    }
    fn role(&self) -> &str {
        &self.role
    }
    fn status(&self) -> &InvitationStatus {
        &self.status
    }
    fn inviter_id(&self) -> &str {
        &self.inviter_id
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl<T: AuthInvitation> From<&T> for Invitation {
    fn from(invitation: &T) -> Self {
        Self {
            id: invitation.id().to_owned(),
            organization_id: invitation.organization_id().to_owned(),
            email: invitation.email().to_owned(),
            role: invitation.role().to_owned(),
            status: invitation.status().clone(),
            inviter_id: invitation.inviter_id().to_owned(),
            expires_at: invitation.expires_at(),
            created_at: invitation.created_at(),
        }
    }
}

impl From<&entities::invitation::Model> for Invitation {
    fn from(model: &entities::invitation::Model) -> Self {
        Self {
            id: model.id.clone(),
            organization_id: model.organization_id.clone(),
            email: model.email.clone(),
            role: model.role.clone(),
            status: InvitationStatus::from(model.status.clone()),
            inviter_id: model.inviter_id.clone(),
            expires_at: model.expires_at,
            created_at: model.created_at,
        }
    }
}

impl AuthVerification for Verification {
    fn id(&self) -> &str {
        &self.id
    }
    fn identifier(&self) -> &str {
        &self.identifier
    }
    fn value(&self) -> &str {
        &self.value
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl AuthTwoFactor for TwoFactor {
    fn id(&self) -> &str {
        &self.id
    }
    fn secret(&self) -> &str {
        &self.secret
    }
    fn backup_codes(&self) -> Option<&str> {
        self.backup_codes.as_deref()
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl<T: AuthTwoFactor> From<&T> for TwoFactor {
    fn from(two_factor: &T) -> Self {
        Self {
            id: two_factor.id().to_owned(),
            secret: two_factor.secret().to_owned(),
            backup_codes: two_factor.backup_codes().map(str::to_owned),
            user_id: two_factor.user_id().to_owned(),
            created_at: two_factor.created_at(),
            updated_at: two_factor.updated_at(),
        }
    }
}

impl From<&entities::two_factor::Model> for TwoFactor {
    fn from(model: &entities::two_factor::Model) -> Self {
        Self {
            id: model.id.clone(),
            secret: model.secret.clone(),
            backup_codes: model.backup_codes.clone(),
            user_id: model.user_id.clone(),
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl AuthApiKey for ApiKey {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn start(&self) -> Option<&str> {
        self.start.as_deref()
    }
    fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }
    fn key_hash(&self) -> &str {
        &self.key_hash
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn refill_interval(&self) -> Option<i64> {
        self.refill_interval
    }
    fn refill_amount(&self) -> Option<i64> {
        self.refill_amount
    }
    fn last_refill_at(&self) -> Option<&str> {
        self.last_refill_at.as_deref()
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn rate_limit_enabled(&self) -> bool {
        self.rate_limit_enabled
    }
    fn rate_limit_time_window(&self) -> Option<i64> {
        self.rate_limit_time_window
    }
    fn rate_limit_max(&self) -> Option<i64> {
        self.rate_limit_max
    }
    fn request_count(&self) -> Option<i64> {
        self.request_count
    }
    fn remaining(&self) -> Option<i64> {
        self.remaining
    }
    fn last_request(&self) -> Option<&str> {
        self.last_request.as_deref()
    }
    fn expires_at(&self) -> Option<&str> {
        self.expires_at.as_deref()
    }
    fn created_at(&self) -> &str {
        &self.created_at
    }
    fn updated_at(&self) -> &str {
        &self.updated_at
    }
    fn permissions(&self) -> Option<&str> {
        self.permissions.as_deref()
    }
    fn metadata(&self) -> Option<&str> {
        self.metadata.as_deref()
    }
}

impl<T: AuthApiKey> From<&T> for ApiKey {
    fn from(api_key: &T) -> Self {
        Self {
            id: api_key.id().to_owned(),
            name: api_key.name().map(str::to_owned),
            start: api_key.start().map(str::to_owned),
            prefix: api_key.prefix().map(str::to_owned),
            key_hash: api_key.key_hash().to_owned(),
            user_id: api_key.user_id().to_owned(),
            refill_interval: api_key.refill_interval(),
            refill_amount: api_key.refill_amount(),
            last_refill_at: api_key.last_refill_at().map(str::to_owned),
            enabled: api_key.enabled(),
            rate_limit_enabled: api_key.rate_limit_enabled(),
            rate_limit_time_window: api_key.rate_limit_time_window(),
            rate_limit_max: api_key.rate_limit_max(),
            request_count: api_key.request_count(),
            remaining: api_key.remaining(),
            last_request: api_key.last_request().map(str::to_owned),
            expires_at: api_key.expires_at().map(str::to_owned),
            created_at: api_key.created_at().to_owned(),
            updated_at: api_key.updated_at().to_owned(),
            permissions: api_key.permissions().map(str::to_owned),
            metadata: api_key.metadata().map(str::to_owned),
        }
    }
}

impl From<&entities::api_key::Model> for ApiKey {
    fn from(model: &entities::api_key::Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model.name.clone(),
            start: model.start.clone(),
            prefix: model.prefix.clone(),
            key_hash: model.key_hash.clone(),
            user_id: model.user_id.clone(),
            refill_interval: model.refill_interval.map(i64::from),
            refill_amount: model.refill_amount.map(i64::from),
            last_refill_at: model.last_refill_at.map(to_rfc3339),
            enabled: model.enabled,
            rate_limit_enabled: model.rate_limit_enabled,
            rate_limit_time_window: model.rate_limit_time_window.map(i64::from),
            rate_limit_max: model.rate_limit_max.map(i64::from),
            request_count: model.request_count.map(i64::from),
            remaining: model.remaining.map(i64::from),
            last_request: model.last_request.map(to_rfc3339),
            expires_at: model.expires_at.map(to_rfc3339),
            created_at: to_rfc3339(model.created_at),
            updated_at: to_rfc3339(model.updated_at),
            permissions: model.permissions.clone(),
            metadata: model.metadata.clone(),
        }
    }
}

impl AuthPasskey for Passkey {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn public_key(&self) -> &str {
        &self.public_key
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn credential_id(&self) -> &str {
        &self.credential_id
    }
    fn counter(&self) -> u64 {
        self.counter
    }
    fn device_type(&self) -> &str {
        &self.device_type
    }
    fn backed_up(&self) -> bool {
        self.backed_up
    }
    fn transports(&self) -> Option<&str> {
        self.transports.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl<T: AuthPasskey> From<&T> for Passkey {
    fn from(passkey: &T) -> Self {
        Self {
            id: passkey.id().to_owned(),
            name: passkey.name().to_owned(),
            public_key: passkey.public_key().to_owned(),
            user_id: passkey.user_id().to_owned(),
            credential_id: passkey.credential_id().to_owned(),
            counter: passkey.counter(),
            device_type: passkey.device_type().to_owned(),
            backed_up: passkey.backed_up(),
            transports: passkey.transports().map(str::to_owned),
            created_at: passkey.created_at(),
        }
    }
}

impl From<&entities::passkey::Model> for Passkey {
    fn from(model: &entities::passkey::Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model.name.clone(),
            public_key: model.public_key.clone(),
            user_id: model.user_id.clone(),
            credential_id: model.credential_id.clone(),
            counter: u64::try_from(model.counter).unwrap_or_default(),
            device_type: model.device_type.clone(),
            backed_up: model.backed_up,
            transports: model.transports.clone(),
            created_at: model.created_at,
        }
    }
}
