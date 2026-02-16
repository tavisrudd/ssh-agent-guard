{
  description = "ssh-agent-guard — policy-enforcing proxy for SSH agent signing";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems f;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.buildGoModule {
            pname = "ssh-agent-guard";
            version = "0.1.0";
            src = ./.;
            vendorHash = "sha256-pOnDHG9engap+82XxsiBEdeDfWja74cTdWczE0DqmAc=";
            ldflags = [ "-s" "-w" ];

            nativeBuildInputs = [ pkgs.makeWrapper ];

            postInstall = ''
              install -Dm755 scripts/ssh-ag-confirm $out/bin/ssh-ag-confirm
              install -Dm755 scripts/ssh-ag-deny $out/bin/ssh-ag-deny
              install -Dm755 scripts/ssh-ag-render-status $out/bin/ssh-ag-render-status

              install -Dm644 ssh-agent-guard.1 $out/share/man/man1/ssh-agent-guard.1
              install -Dm644 ssh-agent-guard-policy.5 $out/share/man/man5/ssh-agent-guard-policy.5

              # Wrap binaries so YubiKey tools are found in systemd's minimal PATH
              for bin in ssh-agent-guard ssh-ag-confirm; do
                wrapProgram $out/bin/$bin \
                  --suffix PATH : ${pkgs.lib.makeBinPath [ pkgs.yubikey-personalization ]}
              done
            '';

            meta = {
              description = "Policy-enforcing proxy for SSH agent signing operations";
              homepage = "https://github.com/tavisrudd/ssh-agent-guard";
              license = pkgs.lib.licenses.bsd3;
              platforms = pkgs.lib.platforms.linux;
            };
          };
        }
      );

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              pkgs.go
              pkgs.gopls
              pkgs.go-md2man
              pkgs.gnum4
            ];
          };
        }
      );

      homeManagerModules.default = import ./module.nix self;
    };
}
