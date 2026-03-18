use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{CreatePasskey, Passkey};

use super::entities::passkey::{ActiveModel, Column, Entity};
use super::{AuthStore, map_db_err};

impl<S: AuthSchema> AuthStore<S> {
    pub async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        let counter = i64::try_from(input.counter)
            .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;

        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            name: Set(input.name),
            public_key: Set(input.public_key),
            user_id: Set(input.user_id),
            credential_id: Set(input.credential_id),
            counter: Set(counter),
            device_type: Set(input.device_type),
            backed_up: Set(input.backed_up),
            transports: Set(input.transports),
            created_at: Set(Utc::now()),
        }
        .insert(self.connection())
        .await
        .map(|model| Passkey::from(&model))
        .map_err(map_db_err)
    }

    pub async fn get_passkey_by_id(&self, id: impl AsRef<str>) -> AuthResult<Option<Passkey>> {
        Entity::find_by_id(id.as_ref().to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Passkey::from(&model)))
            .map_err(map_db_err)
    }

    pub async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        Entity::find()
            .filter(Column::CredentialId.eq(credential_id))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Passkey::from(&model)))
            .map_err(map_db_err)
    }

    pub async fn list_passkeys_by_user(
        &self,
        user_id: impl AsRef<str>,
    ) -> AuthResult<Vec<Passkey>> {
        Entity::find()
            .filter(Column::UserId.eq(user_id.as_ref()))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Passkey::from).collect())
            .map_err(map_db_err)
    }

    pub async fn update_passkey_counter(
        &self,
        id: impl AsRef<str>,
        counter: u64,
    ) -> AuthResult<Passkey> {
        let Some(model) = Entity::find_by_id(id.as_ref().to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("Passkey not found"));
        };

        let mut active = model.into_active_model();
        active.counter = Set(i64::try_from(counter)
            .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?);
        active
            .update(self.connection())
            .await
            .map(|model| Passkey::from(&model))
            .map_err(map_db_err)
    }

    pub async fn update_passkey_name(
        &self,
        id: impl AsRef<str>,
        name: &str,
    ) -> AuthResult<Passkey> {
        let Some(model) = Entity::find_by_id(id.as_ref().to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("Passkey not found"));
        };

        let mut active = model.into_active_model();
        active.name = Set(name.to_owned());
        active
            .update(self.connection())
            .await
            .map(|model| Passkey::from(&model))
            .map_err(map_db_err)
    }

    pub async fn delete_passkey(&self, id: impl AsRef<str>) -> AuthResult<()> {
        Entity::delete_by_id(id.as_ref().to_owned())
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }
}
