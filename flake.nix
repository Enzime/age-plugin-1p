{
  description = "An age plugin for using SSH keys from 1Password";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  inputs.flake-parts.url = "github:hercules-ci/flake-parts";
  inputs.flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";

  inputs.flake-compat.url = "github:edolstra/flake-compat";

  inputs.wrapper-manager.url = "github:viperML/wrapper-manager";
  inputs.wrapper-manager.inputs.nixpkgs.follows = "nixpkgs";

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      perSystem = { self', pkgs, lib, ... }: {
        packages.age = (inputs.wrapper-manager.lib {
          inherit pkgs;
          modules = [
            {
              wrappers.age = {
                basePackage = pkgs.age;
                pathAdd = [ self'.packages.age-plugin-1p ];
              };
            }
          ];
        }).config.wrappers.age.wrapped;

        packages.age-plugin-1p = pkgs.buildGoModule {
          pname = "age-plugin-1p";
          version = "0.1.0";
          src = ./.;
          vendorHash = "sha256-WrdwhlaqciVEB2L+Dh/LEeSE7I3+PsOTW4c+0yOKzKY=";
        };

        packages.default = pkgs.buildEnv {
          name = "age-with-plugins";
          paths = builtins.attrValues {
            inherit (self'.packages) age age-plugin-1p;
          };
          meta.mainProgram = "age-plugin-1p";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = builtins.attrValues {
            inherit (pkgs) go gopls go-tools;
            inherit (self'.packages) age age-plugin-1p;
          };
        };
      };
    };
}
