use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, DatabaseAdapter,
};

pub struct DeviceAuthorizationPlugin {
    config: DeviceAuthorizationConfig,
}

#[derive(Debug, Clone, better_auth_core::PluginConfig)]
#[plugin(name = "DeviceAuthorizationPlugin")]
pub struct DeviceAuthorizationConfig {
    #[config(default = false)]
    pub enabled: bool,

    #[config(default = "/device".to_string())]
    pub verification_uri: String,

    #[config(default = 5)]
    pub interval: i64,

    #[config(default = 1800)]
    pub expires_in: i64,
}

better_auth_core::impl_auth_plugin! {
    DeviceAuthorizationPlugin, "device-authorization";
    routes {
        post "/device/code" => handle_code, "device_code";
        post "/device/token" => handle_token, "device_token";
        post "/device/approve" => handle_approve, "device_approve";
        post "/device/deny" => handle_deny, "device_deny";
    }
}

// ---------------------------------------------------------------------------
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

impl DeviceAuthorizationPlugin {
    async fn handle_code<DB: DatabaseAdapter>(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        if !self.config.enabled {
            return Err(AuthError::not_found("Not Found"));
        }
        todo!()
    }

    async fn handle_token<DB: DatabaseAdapter>(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        if !self.config.enabled {
            return Err(AuthError::not_found("Not Found"));
        }
        todo!()
    }

    async fn handle_approve<DB: DatabaseAdapter>(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        if !self.config.enabled {
            return Err(AuthError::not_found("Not Found"));
        }
        todo!()
    }

    async fn handle_deny<DB: DatabaseAdapter>(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        if !self.config.enabled {
            return Err(AuthError::not_found("Not Found"));
        }
        todo!()
    }
}
