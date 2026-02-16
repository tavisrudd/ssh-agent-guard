self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.ssh-agent-guard;
in
{
  options.services.ssh-agent-guard = {
    enable = lib.mkEnableOption "ssh-agent-guard, a policy-enforcing proxy for SSH agent signing";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "The ssh-agent-guard package.";
    };

    listenPath = lib.mkOption {
      type = lib.types.str;
      default = "%t/ssh-agent-guard.sock";
      description = ''
        Proxy listen socket path. Supports systemd specifiers:
        %t = XDG_RUNTIME_DIR, %h = HOME.
      '';
    };

    upstreamPath = lib.mkOption {
      type = lib.types.str;
      default = "%t/gnupg/S.gpg-agent.ssh";
      description = "Upstream SSH agent socket path (systemd specifiers supported).";
    };

    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "%h/.local/state/ssh-ag";
      description = "Directory for YAML event logs and status files.";
    };

    policyPath = lib.mkOption {
      type = lib.types.str;
      default = "%h/.config/ssh-ag/policy.yaml";
      description = "Path to the policy YAML configuration file.";
    };

    verbose = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Log all operations including key listing requests.";
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = { SSH_AG_EXCLUDE_OUTPUTS = "DSI-1"; };
      description = "Extra environment variables for the systemd service.";
    };
  };

  config = lib.mkIf cfg.enable {
    home.packages = [ cfg.package ];

    systemd.user.services.ssh-agent-guard = {
      Unit = {
        Description = "SSH Agent Guard (policy-enforcing proxy)";
        After = [ "gpg-agent-ssh.socket" ];
      };
      Service = {
        ExecStart = lib.concatStringsSep " " ([
          "${cfg.package}/bin/ssh-agent-guard"
          "--listen"
          cfg.listenPath
          "--upstream"
          cfg.upstreamPath
          "--state-dir"
          cfg.stateDir
          "--policy"
          cfg.policyPath
        ] ++ lib.optional cfg.verbose "--verbose");
        ExecReload = "/bin/sh -c 'kill -HUP $MAINPID'";
        Restart = "on-failure";
        RestartSec = 5;
      }
      // lib.optionalAttrs (cfg.environment != { }) {
        Environment = lib.mapAttrsToList (k: v: "${k}=${v}") cfg.environment;
      };
      Install = {
        WantedBy = [ "default.target" ];
      };
    };
  };
}
