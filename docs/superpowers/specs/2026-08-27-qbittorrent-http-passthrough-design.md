# qBittorrent HTTP Passthrough Design

## Problem

MOLE currently exposes qBittorrent's Web API through a raw `socat` TCP relay. qBittorrent 5.2.3 advertises HTTP keep-alive but closes idle HTTP connections after seven seconds. Sonarr and Radarr retain those advertised connections and can reuse them after qBittorrent has closed the upstream socket, producing intermittent `Connection reset by peer` health alerts.

TCP keepalive settings do not solve this HTTP lifetime mismatch because their probe interval is longer than qBittorrent's HTTP idle timeout.

## Goals

- Offer an HTTP-aware passthrough that prevents clients from retaining qBittorrent upstream connections.
- Preserve the existing bind address and port used by Arr applications and Qui.
- Leave MOLE's WireGuard namespace, qBittorrent process, torrent traffic, and direct MOLE API path unchanged.
- Preserve `socat` as the backward-compatible default.
- Make the mode explicit, validated, observable, and reversible.

## Configuration

Add `QB_PASSTHROUGH_MODE=socat|nginx` to `/etc/mole/config`. The default is `socat` for existing installations. Invalid values fail configuration validation and passthrough setup.

This host will opt into `nginx` after the repository change is tested.

## Runtime Design

The existing `qbittorrent-passthrough.service` remains the lifecycle boundary. It imports the root-owned MOLE configuration through systemd and executes a MOLE-owned wrapper at `/usr/local/lib/mole/qbittorrent-passthrough.sh`. The wrapper also sources a directly readable configuration file when run outside systemd.

In `socat` mode, the wrapper retains the current TCP relay behavior.

In `nginx` mode, the wrapper writes an isolated Nginx configuration into the systemd runtime directory and starts Nginx in the foreground. It does not use or modify the host's website Nginx configuration.

The generated proxy configuration must include:

```nginx
proxy_http_version 1.1;
proxy_set_header Connection close;
proxy_set_header Host <vpn-veth-ip>:<qbit-port>;
client_max_body_size 64m;
proxy_request_buffering off;
proxy_buffering off;
proxy_connect_timeout 5s;
proxy_send_timeout 100s;
proxy_read_timeout 100s;
```

`Connection close` is the key behavior: downstream clients cannot cache a connection beyond qBittorrent's upstream lifetime. The upstream `Host` value is explicit because qBittorrent validates the host header.

The service uses a dynamic unprivileged user by default. The Nginx process uses stderr logging, disables access logs, binds only the configured passthrough address, and stores its PID and temporary files in the service runtime directory. Existing systemd user drop-ins remain compatible.

## Dependency and Failure Behavior

- `socat` mode requires `socat`.
- `nginx` mode requires the `nginx` executable.
- Missing dependencies are reported as errors; MOLE never silently changes modes.
- The runtime wrapper validates mode, bind address, upstream address, and port before starting.
- Service restart behavior remains managed by systemd.

## Installation and Upgrade

`mole qbittorrent passthrough` becomes an idempotent reconciliation command: it validates the selected mode, regenerates the wrapper and service, reloads systemd, and starts the service if necessary.

An ordinary MOLE upgrade installs the new code but does not implicitly switch modes or restart qBittorrent. Operators opt into Nginx by setting the configuration value and reconciling the passthrough service.

## Rollback

Set `QB_PASSTHROUGH_MODE=socat` and rerun `mole qbittorrent passthrough`. The listener address and port do not change, so clients require no reconfiguration. A service/config backup is taken before the live rollout.

## Validation

- Unit tests cover mode defaults, accepted/rejected values, dependency selection, service generation, and required Nginx directives.
- Existing focused tests must remain green and the full suite must introduce no failures beyond the recorded baseline.
- `systemd-analyze verify` validates the installed unit.
- Runtime validation checks the listener, MOLE and qBittorrent health, Sonarr/Radarr tests, a downstream connection reused after more than seven seconds, and logs across multiple health-check cycles.

## Non-Goals

- Changing qBittorrent's torrent listening port or VPN routing.
- Moving MOLE's own qBittorrent API calls through the passthrough.
- Modifying the host's general-purpose Nginx configuration.
- Changing the separate privnzb project.
