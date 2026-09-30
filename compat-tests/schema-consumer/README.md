# Generated schema consumer

Run from the repository root:

```sh
devenv shell -- ./scripts/consumer-check.sh
```

The script runs the public CLI with every supported schema plugin. The script writes generated code to a temporary directory, then formats, lints, and tests this independent Cargo package. The package uses the public `better-auth` dependency and does not use the internal bundled schema.

The test creates SQLite tables and exercises registration, login, a protected Axum route, API Key creation, and TOTP enrollment. The test verifies that subsequent password login requires a second factor. Database writes verify email, provider account, and two-factor uniqueness, plus session foreign keys.

The generated `create_auth_tables` function initializes an empty database. Application-owned versioned migrations must handle existing databases and later plugin additions.
