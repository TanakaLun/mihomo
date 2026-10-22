# Tailscale inbound (subnet router / exit node)

This document covers the Tailscale gateway capabilities of the Tailscale
outbound: accepting traffic that arrives from the tailnet, advertising routes
as a subnet router, and declaring the node as an exit node. Traffic arriving
from the tailnet enters the mihomo rule engine as an `IN-TYPE,TAILSCALE` flow
and selects proxies by the normal rules.

The feature is part of the Tailscale outbound, so it requires a build with the
`with_gvisor` tag and the `no_tailscale` tag unset. The upstream
`github.com/metacubex/tailscale` module supplies the `tsnet` server the
outbound is built on.

## Supported environments

- Operating systems: Linux, Windows, macOS, Android (any OS `tsnet` supports).
- Build tags: the outbound is compiled with `with_gvisor`; it is replaced by a
  stub that returns an explicit unsupported error when `no_tailscale` is set or
  `with_gvisor` is missing.
- The inbound handlers depend on the tsnet fallback flow handlers, which are
  available in all upstream `metacubex/tailscale` builds used by this branch.

## Configuration

```yaml
proxies:
  - name: TS
    type: tailscale
    hostname: my-gateway
    auth-key: tskey-auth-xxxxx
    udp: true
    accept-routes: true               # route tailnet subnets into the kernel
    listen-port: 41641                # fixed magicsock port (optional)
    advertise-routes:                 # advertise as a subnet router
      - 192.168.0.0/24
    advertise-exit-node: true         # declare this node as an exit node
```

Field behavior:

- `listen-port`: fixed UDP port for magicsock. Leave unset for an ephemeral
  port. When the outbound runs alongside TUN, exclude this port from the TUN
  device to avoid a traffic loop (`tun.exclude-src-port: [41641]`).
- `advertise-routes`: a list of CIDR prefixes this node routes for the
  tailnet. Routes are validated at startup; an invalid prefix is refused when
  the outbound is created.
- `advertise-exit-node`: when true, the node declares itself an exit node and
  advertises `0.0.0.0/0` and `::/0` (all of IPv4 and IPv6).

## How it works

The Tailscale outbound runs a `tsnet.Server`. When advertise routes are
configured, the outbound registers fallback flow handlers on the server so
that traffic arriving from the tailnet for an advertised route is delivered to
the mihomo rule engine:

- TCP: `RegisterFallbackTCPHandler` hands connections to the tunnel with a
  metadata whose connection type is `TAILSCALE`.
- UDP: `RegisterFallbackUDPHandler` reads packets, bounds them with a shared
  buffer pool, and hands them to the tunnel; replies are written back to the
  original tailnet peer.

Flows whose destination is one of the node's own Tailscale IPs are left to
tsnet's default behavior (explicit listeners / reject); they are not sent into
the rule engine.

The outbound starts eagerly as soon as advertise routes are configured, and
retries with backoff until the tsnet backend reaches the running state; a
transient failure (state files, control-plane reachability, Android Doze) must
not make the gateway unavailable for the rest of the configuration.

## Semantics and boundaries

- Inbound flows carry `Type: TAILSCALE`, so rules such as
  `IN-TYPE,TAILSCALE,智能优选` match them; use this to route tailnet traffic
  through a distinct group before general rules.
- The tailnet uses `100.64.0.0/10` (IPv4) and `fd7a:115c:a1e0::/48` (IPv6).
  Put Tailscale routes *before* `GEOIP,CN` and private-network DIRECT rules:
  ```yaml
  rules:
    - IP-CIDR,100.64.0.0/10,TS,no-resolve
    - IP-CIDR6,fd7a:115c:a1e0::/48,TS,no-resolve
    - GEOIP,CN,DIRECT
    - MATCH,智能优选
  ```
- When this node is an exit node, the exit traffic of other tailnet devices
  also follows the mihomo rules — the tailnet reaches the internet through
  whatever the rules select.
- `accept-routes` only affects local routing of other nodes' advertised
  routes; it does not by itself make this node an exit node.
- Route advertisement (`advertise-routes` / `advertise-exit-node`) requires a
  tunnel (the `TunnelForAPI` passed to all proxies by the config loader). If
  no tunnel is available the outbound still runs but inbound flows are
  rejected.

## Verification

- With a working auth key, the node appears in the tailnet with the configured
  hostname. Configured advertise routes show up as advertised routes of the
  peer.
- Traffic from another tailnet device to an advertised route is logged by
  mihomo with `type: Tailscale`; check `IN-TYPE,TAILSCALE` grouping by
  selecting a dedicated group in the rules above.
- Run `go test -tags with_gvisor -run Tailscale ./adapter/outbound/` — the
  package tests cover watcher reconnect, startup retries, advertise-route
  parsing and backend readiness transitions.

## FAQ / troubleshooting

- **Tailnet peers report the node as unavailable**: check that the tailscale
  backend reached the running state (`backend is not running / retrying`);
  auth key expiry or a changing network are the usual causes, and the eager
  retry loop logs each attempt.
- **Exit traffic loops through TUN**: exclude the magicsock port from the TUN
  device (`tun.exclude-src-port`), and do not put the same physical NIC under
  both a TUN auto-route and a shared eBPF inbound.
- **Inbound flows are rejected though routes are advertised**: the outbound
  had no tunnel at creation (config loader did not pass one); check the log
  message "advertise-routes configured but no tunnel available".