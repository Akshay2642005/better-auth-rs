use better_auth_schema_registry::{self as registry, EntityRole, ExtraEntitySchema, FieldDef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub(crate) fn list_plugins() -> Vec<&'static str> {
    registry::plugin_schemas().iter().map(|p| p.name).collect()
}

pub(crate) fn generate_schema(plugins: &[String]) -> String {
    let mut user = registry::core_fields(EntityRole::User).to_vec();
    let mut session = registry::core_fields(EntityRole::Session).to_vec();
    let mut extra_entities: Vec<&ExtraEntitySchema> = Vec::new();
    for plugin_name in plugins {
        if let Some(schema) = registry::plugin_schemas()
            .iter()
            .find(|p| p.name == plugin_name.as_str())
        {
            user.extend_from_slice(schema.user_fields);
            session.extend_from_slice(schema.session_fields);
            extra_entities.extend(schema.extra_entities.iter());
        }
    }
    let core_entities = [
        ExtraEntitySchema {
            mod_name: "user",
            table_name: "users",
            role: Some(EntityRole::User),
            fields: &[],
        },
        ExtraEntitySchema {
            mod_name: "session",
            table_name: "sessions",
            role: Some(EntityRole::Session),
            fields: &[],
        },
        ExtraEntitySchema {
            mod_name: "account",
            table_name: "accounts",
            role: Some(EntityRole::Account),
            fields: &[],
        },
        ExtraEntitySchema {
            mod_name: "verification",
            table_name: "verifications",
            role: Some(EntityRole::Verification),
            fields: &[],
        },
    ];
    let mut entities = Vec::new();
    let mut tables = Vec::new();
    let mut indexes = Vec::new();
    for entity in core_entities.iter().chain(extra_entities) {
        let fields = match entity.role {
            Some(EntityRole::User) => user.as_slice(),
            Some(EntityRole::Session) => session.as_slice(),
            Some(role) => registry::core_fields(role),
            None => entity.fields,
        };
        entities.push(gen_entity(entity, fields));
        tables.push(gen_table(entity));
        indexes.extend(gen_indexes(entity, fields));
    }
    let tokens = quote! {
        use better_auth::AuthSchema;
        use better_auth::seaorm::sea_orm;
        use better_auth::seaorm::sea_orm::entity::prelude::*;
        use better_auth::seaorm::sea_orm::{ConnectionTrait, Schema};
        use better_auth::seaorm::sea_orm::sea_query::{Alias, ForeignKey, ForeignKeyAction, Index};
        use better_auth::seaorm::AuthEntity;

        #(#entities)*

        pub struct AppAuthSchema;

        impl AuthSchema for AppAuthSchema {
            type User = user::Model;
            type Session = session::Model;
            type Account = account::Model;
            type Verification = verification::Model;
        }

        /// Create auth tables in an empty database.
        ///
        /// Call this scaffold from the application's initial migration.
        /// Use versioned migrations to change existing tables.
        pub async fn create_auth_tables(database: &impl ConnectionTrait) -> Result<(), sea_orm::DbErr> {
            let schema = Schema::new(database.get_database_backend());
            for statement in [#(#tables,)*] {
                let _ = database.execute(&statement).await?;
            }
            for statement in [#(#indexes,)*] {
                let _ = database.execute(&statement).await?;
            }
            Ok(())
        }
    };
    #[expect(
        clippy::expect_used,
        reason = "generated from hardcoded registry; parse failure is a bug"
    )]
    let file = syn::parse2(tokens).expect("generated code should be valid syntax");
    prettyplease::unparse(&file)
}

fn gen_entity(entity: &ExtraEntitySchema, fields: &[FieldDef]) -> TokenStream {
    let mod_ident = format_ident!("{}", entity.mod_name);
    let table_name = entity.table_name;
    let field_tokens = fields.iter().map(|field| {
        let name = format_ident!("{}", field.name);
        #[expect(
            clippy::panic,
            reason = "type strings come from hardcoded registry; parse failure is a bug"
        )]
        let ty: syn::Type = syn::parse_str(field.ty).unwrap_or_else(|e| {
            panic!(
                "invalid type `{}` for field `{}`: {e}",
                field.ty, field.name
            )
        });
        let column_attr = field
            .column_name
            .map(|column| quote! { #[sea_orm(column_name = #column)] });
        let primary_key = field
            .is_primary_key
            .then(|| quote! { #[sea_orm(primary_key, auto_increment = false)] });
        quote! {
            #column_attr
            #primary_key
            pub #name: #ty,
        }
    });
    let derives = if entity.role.is_some() {
        let role = entity.mod_name;
        quote! {
            #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
            #[auth(role = #role)]
        }
    } else {
        quote! { #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)] }
    };
    quote! {
        mod #mod_ident {
            use super::*;
            #derives
            #[sea_orm(table_name = #table_name)]
            pub struct Model { #(#field_tokens)* }
            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        }
    }
}

fn gen_table(entity: &ExtraEntitySchema) -> TokenStream {
    let module = format_ident!("{}", entity.mod_name);
    let table = entity.table_name;
    let foreign_keys = registry::entity_foreign_keys(table)
        .iter()
        .map(|(column, target)| {
            let name = format!("fk_{table}_{column}");
            quote! {
                .foreign_key(ForeignKey::create()
                    .name(#name)
                    .from(Alias::new(#table), Alias::new(#column))
                    .to(Alias::new(#target), Alias::new("id"))
                    .on_delete(ForeignKeyAction::Cascade))
            }
        });
    quote! { schema.create_table_from_entity(#module::Entity) #(#foreign_keys)* .to_owned() }
}

fn gen_indexes(entity: &ExtraEntitySchema, fields: &[FieldDef]) -> Vec<TokenStream> {
    let table = entity.table_name;
    registry::entity_indexes(table).iter()
        .filter(|index| index.columns.iter().all(|column| fields.iter().any(|field| field.column_name.unwrap_or(field.name) == *column)))
        .map(|index| {
            let name = format!("idx_{table}_{}", index.columns.join("_"));
            let columns = index.columns.iter().map(|column| quote! { .col(Alias::new(#column)) });
            let unique = index.unique.then(|| quote! { .unique() });
            quote! { Index::create().name(#name).table(Alias::new(#table)) #(#columns)* #unique .to_owned() }
        })
        .collect()
}
