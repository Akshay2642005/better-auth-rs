//! Configuration types beyond the root `AuthConfig` entrypoint.

pub use better_auth_core::config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, Argon2Config,
    BearerConfig, CookieAttributes, CookieCacheConfig, CookieCacheStrategy, CookieOverride,
    CrossSubDomainConfig, IpAddressConfig, JwtConfig, OAuthStateStrategy, PasswordConfig, SameSite,
    SessionConfig, SessionFieldConfig, core_paths, extract_origin,
};
