{ pkgs, ... }:

{
  packages = [ pkgs.bun pkgs.pkg-config pkgs.openssl ];

  languages.rust = {
    enable = true;
    channel = "stable";
  };

  scripts.check.exec = ''
    set -euo pipefail
    bun install --cwd compat-tests/reference-server --frozen-lockfile
    bun install --cwd compat-tests/client-tests --frozen-lockfile
    cargo fmt --all -- --check
    cargo clippy --workspace --locked -- -D warnings
    cargo clippy --workspace --locked --features axum -- -D warnings
    cargo test --workspace --locked
    ./scripts/alignment-check.sh
  '';

  enterTest = "check";
}
