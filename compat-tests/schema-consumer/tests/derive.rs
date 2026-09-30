include!(env!("BETTER_AUTH_GENERATED_SCHEMA"));

#[derive(better_auth::AuthSchema)]
#[auth(
    user = "user::Model",
    session = "session::Model",
    account = "account::Model",
    verification = "verification::Model"
)]
pub struct Combined;

#[derive(better_auth::AuthSchema)]
#[auth(user = "user::Model")]
#[auth(session = "session::Model")]
#[auth(account = "account::Model")]
#[auth(verification = "verification::Model")]
pub struct Separate;
