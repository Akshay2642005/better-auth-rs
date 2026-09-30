{ pkgs, ... }:

{
  packages = [ pkgs.bun pkgs.pkg-config pkgs.openssl ];

  languages.rust = {
    enable = true;
    channel = "stable";
  };

  scripts.check.exec = "./scripts/check.sh";

  enterTest = "check";
}
