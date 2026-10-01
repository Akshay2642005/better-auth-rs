use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, LitStr, Type};

pub(crate) fn derive_auth_schema(input: &DeriveInput) -> TokenStream {
    let [user, session, account, verification] = match parse_types(input) {
        Ok(value) => value,
        Err(err) => return err.to_compile_error(),
    };
    let ident = &input.ident;

    quote! {
        impl ::better_auth::__private_core::schema::AuthSchema for #ident {
            type User = #user;
            type Session = #session;
            type Account = #account;
            type Verification = #verification;
        }
    }
}

fn parse_types(input: &DeriveInput) -> Result<[Type; 4], syn::Error> {
    let mut fields = [
        ("user", None),
        ("session", None),
        ("account", None),
        ("verification", None),
    ];
    for attr in &input.attrs {
        if !attr.path().is_ident("auth") {
            continue;
        }

        attr.parse_nested_meta(|meta| {
            let (_, ty) = fields
                .iter_mut()
                .find(|(key, _)| meta.path.is_ident(key))
                .ok_or_else(|| meta.error("expected user, session, account, or verification"))?;
            if ty.is_some() {
                return Err(meta.error("duplicate AuthSchema model"));
            }
            *ty = Some(meta.value()?.parse::<LitStr>()?.parse()?);
            Ok(())
        })?;
    }

    let [user, session, account, verification] = fields.map(|(key, ty)| {
        ty.ok_or_else(|| {
            syn::Error::new_spanned(
                input,
                format!("missing #[auth({key} = \"path::to::Model\")] attribute for AuthSchema"),
            )
        })
    });
    Ok([user?, session?, account?, verification?])
}

#[cfg(test)]
mod tests {
    use super::parse_types;

    #[test]
    fn rejects_incomplete_or_ambiguous_schema_declarations() {
        let cases = [
            (
                syn::parse_quote! {
                    #[auth(user = "user::Model")]
                    struct Missing;
                },
                "missing #[auth(session = \"path::to::Model\")]",
            ),
            (
                syn::parse_quote! {
                    #[auth(user = "user::Model", user = "other::Model")]
                    struct Duplicate;
                },
                "duplicate AuthSchema model",
            ),
            (
                syn::parse_quote! {
                    #[auth(users = "user::Model")]
                    struct Unknown;
                },
                "expected user, session, account, or verification",
            ),
        ];
        for (input, message) in cases {
            assert!(
                matches!(parse_types(&input), Err(error) if error.to_string().contains(message))
            );
        }
    }
}
