{ pkgs, ... }:

{
  packages = [ pkgs.bun pkgs.nodejs pkgs.pnpm pkgs.pkg-config pkgs.openssl ];

  languages.rust = {
    enable = true;
    channel = "stable";
  };

  scripts.check.exec = "./scripts/check.sh";

  enterTest = "check";
}
