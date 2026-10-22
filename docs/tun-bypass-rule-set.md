# TUN kernel bypass (route-exclude-address-set / route-exclude-address)

Traffic whose **destination CIDR matches a `route-exclude-address-set`
rule-set or a `route-exclude-address` static CIDR is bypassed at the kernel
level, without ever entering the TUN device** — it does not reach the mihomo
userspace protocol stack, giving near-bare-metal direct performance. It is the
TUN equivalent of the eBPF transparent inbound's (`ebpf-inbound.md`)
`bypass-rule-set` semantics, and is unified on sing-tun's native
`route-exclude-*` family:

- All platforms: the TUN inbound publishes the rule-set CIDRs into the shared
  **component/bypass** registry, and the DNS fake-ip middleware answers
  domains that resolve inside the set with their **real IP** (instead of a
  fake-ip) so the bypass can actually engage;
- Windows: in addition, concrete routes to these CIDRs are installed on the
  **physical interface** (next hop taken from the current best physical
  route); matching traffic follows the longest-prefix route straight to the
  physical NIC and **never enters the TUN** — it does not even pass through
  the wintun ring buffer or the userspace stack, so the gain exceeds the eBPF
  bypass.

> `route-exclude-address-set` (rule-set driven, hot-reloadable) and
> `route-exclude-address` (static CIDRs) are two sources of the same bypass
> pipeline: the static set is published when the TUN starts, the rule-set set
> when it loads or hot-reloads. Both may be configured at once and take
> effect additively.

## Supported environments

| Capability | Linux / Android | Windows | macOS |
|---|---|---|---|
| fake-ip → real IP linkage (DNS) | ✅ (published by both TUN and eBPF) | ✅ | ✅ |
| kernel route bypass (never enters TUN) | via nftables/HW schemes; none by default on the TUN side | ✅ (this feature) | ❌ (no route reconcile yet) |
| requires admin rights | — | ✅ (route modification + wintun) | — |

> The eBPF inbound's own kernel bypass (cgroup/TC `DecisionPass`) is outside
> the scope of this page. This page describes the **TUN** inbound capability;
> the two can coexist (eBPF handles the local host, TUN handles everything
> else). The eBPF inbound keeps `local.bypass-rule-set` / `shared.bypass-rule-set`
> naming (matching sing-ebpf/sing-box upstream); only the TUN side uses the
> `route-exclude-*` vocabulary.

## Configuration

```yaml
tun:
  enable: true
  stack: mixed
  dns-hijack:
    - any:53
  auto-route: true          # recommended: without auto-route the TUN does not
                            # take over the default route and the Windows
                            # bypass routes are meaningless
  # strict-route: true      # optional; the current WFP filter does not block
                            # bypassed traffic and they can coexist

  route-exclude-address-set:  # rule-set tags; matched destination CIDRs bypass
    - geoip-cn              # accepts behavior: ipcidr (whole extraction) or
                            # behavior: classical (extracts its IP-CIDR rules)
  route-exclude-address:      # (optional) static CIDRs to bypass, no rule-set;
    - 100.64.0.0/10           # stacked on top of the rule-set above
  # route-address:            # override the default route table (avoid
  #   - 0.0.0.0/1             # prefixes as wide as the bypass ones)
  #   - 128.0.0.0/1

rule-providers:
  geoip-cn:
    type: http
    behavior: ipcidr        # ipcidr / classical both work for route-exclude-address-set
    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geoip/cn.txt"
    path: ./ruleset/geoip-cn.txt
    interval: 86400

dns:
  enable: true
  enhanced-mode: fake-ip    # the DNS linkage happens automatically under
                            # fake-ip; redir-host gets real IPs naturally
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
```

> Migration note: the older `bypass-rule-set` / `bypass-address` names were
> folded into `route-exclude-address-set` / `route-exclude-address` — the
> semantics and effect are identical (the latter additionally gets sing-tun's
> native exclusion). Just rename the keys.

Field behavior:

- `route-exclude-address-set`: rule provider tags whose destination CIDRs are
  bypassed in kernel. `behavior: ipcidr` extracts the whole set, `classical`
  extracts its `IP-CIDR` rules. Hot-reloads with the provider.
- `route-exclude-address`: static CIDRs bypassed in kernel, no rule-set
  needed. Stacked with the rule-set source.
- `route-address`: optional override of the default route table; useful when
  the bypass prefixes would otherwise be exactly as wide as a TUN route.
- Both sources publish to `component/bypass` on TUN start or rule-set reload;
  the TUN inbound removes exactly what it published (reference counted) on
  close.

## How it works (Windows)

1. **Publish**: on TUN start / rule-set hot-reload, the union of
   `route-exclude-address-set` rule-set CIDRs and static `route-exclude-address`
   CIDRs (merged automatically by `netipx.IPSet`) is published to
   `component/bypass`; on TUN close the published part is removed
   (reference counted, no residue).
2. **DNS linkage**: with a bypass set present, the fake-ip middleware real-
   resolves A/AAAA first; answers inside the set are returned as real IPs so
   the connection's destination can hit the bypass route (instead of the
   fake-ip range). Hosts with an established fake mapping keep the fake
   address and are not real-resolved again.
3. **Route install**: for each bypass prefix, find a physical route in the
   route table that **fully covers** it (excluding the TUN interface; longest
   prefix wins, same length takes the lower metric), then copy its
   `prefix + next hop + interface LUID + metric` into a **more specific
   physical route** and install it. Longest-prefix matching then keeps that
   traffic off the TUN's default route.
4. **Hot update**: on rule-set update do a delta (add before delete); on
   network changes (Wi-Fi / wired / VPN switches) reselect the next hop and
   rebuild; on exit remove the installed routes.

## Semantics and boundaries

- **Bypass = never enters the TUN**: traffic matching the set goes straight
  to the physical NIC at the kernel level and mihomo rules never see it. This
  matches the eBPF `DecisionPass` semantics — put only destinations you want
  to always go direct in the set.
- **Destination CIDR only**: `bypass-port`, process and UID dimensions cannot
  be expressed at the Windows route layer; that traffic still goes through the
  TUN (no kernel gain).
- **Prefixes wider than a covering TUN route are skipped** (safe fallback to
  in-TUN proxying), e.g. a `0.0.0.0/0` or `0.0.0.0/1` in the set is not
  installed as a physical route.
- **Prefixes without a covering physical route are skipped**: e.g. a
  destination only present in the TUN's own on-link network; traffic still
  goes through the TUN and is proxied — the safe direction.
- **Protected prefixes never bypass**: the TUN's own address range and
  `loopback-address` are never bypassed.
- **fake-ip note**: do not put the fake-ip range (default `198.18.0.0/16`)
  into the bypass set; the Windows side only defends the TUN's own address
  today, and geoip-class sets do not overlap it.
- Established connections are unaffected by new routes (routes only affect
  new connections).

## Verification (Windows)

```powershell
# 1) Confirm the bypass route lands on the physical NIC (not Meta/TUN)
Get-NetRoute -DestinationPrefix 1.0.0.0/24

# 2) Direct to the real IP (a domain in the set should answer its real IP)
curl.exe --resolve www.example.com:443:1.2.3.4 https://www.example.com/

# 3) After hot-reloading the rule-set, re-check the routes
# 4) After closing mihomo, confirm all bypass routes are gone
Get-NetRoute | Where-Object { $_.InterfaceAlias -ne "Meta" -and $_.RouteMetric -eq 0 } | Select-Object DestinationPrefix, NextHop, InterfaceAlias
```

FAQ:

- **Does it need admin?** Yes (same privilege level as wintun plus rewriting
  the route table).
- **Why does the bypass prefix's metric equal the physical default route's?**
  Deliberate: it copies the metric of the best covering physical route, so
  when several equal-width physical paths exist (home Wi-Fi + VPN), Windows
  arbitrates — traffic goes "wherever it used to go".
- **Why don't I see the route?** The rule-set has not finished loading / the
  prefix is wider than a TUN route / there is no covering physical route /
  `auto-route` is off. A Warn is logged.

## Troubleshooting

Walk this decision tree to narrow it down in a few minutes:

1. **Confirm the publish**: after start / rule-set reload there should be a
   `[TUN] bypass-rule-set: N CIDRs published (1.0.1.0/24, ...)` log.
   - N=0: the rule-set is not loaded yet or its behavior is not
     ipcidr/classical (a Warn is logged).
2. **Confirm the route is installed** (take any prefix from the log, e.g.
   `1.0.1.0/24`):
   ```powershell
   Get-NetRoute -DestinationPrefix 1.0.1.0/24 | fl DestinationPrefix, InterfaceAlias, NextHop, RouteMetric
   ```
   - Present with `InterfaceAlias` = a physical NIC (not Meta) → route OK,
     skip to step 4.
   - Missing → a `apply bypass routes:` Warn should exist (commonly: the TUN
     interface LUID could not be resolved / the prefix is covered by a
     protected range / missing permissions). Paste the whole Warn.
3. **Confirm the traffic really stays out of mihomo**: in mihomo →
   Connections, connect to an IP inside the set; a missing connection = the
   bypass worked; a present one = it did not.
4. **Domain tests must use the real IP**:
   - `enhanced-mode: redir-host`: real IPs by nature, works directly.
   - `enhanced-mode: fake-ip`: the DNS linkage only works if the bypass set is
     published before the domain's first query. If the rule-set loads later
     than the first query, the old fake mapping keeps the domain on the TUN —
     verify with `curl --resolve <domain>:443:<realIP> https://<domain>/`, or
     use the `dns.flush-fake-ip` API to drop stale mappings first.
5. **Pure-IP test** (skips DNS and isolates the route layer fast):
   ```powershell
   # -S picks the local physical NIC IP
   Test-NetConnection 1.2.3.4 -InformationLevel Detailed
   ```

### Common failure logs

| Log | Meaning / action |
|---|---|
| `republished N CIDRs (...)` | The set is published (N should be in the thousands); if 0, check rule-set loading |
| `apply bypass routes: route: tun interface "meta" not found yet` | Early start, TUN not ready; auto-retried later, safe to ignore |
| `CreateIpForwardEntry2 <prefix> via <gw> failed: Element not found` | WinAPI add failed; newer builds retry once and fall back to `route.exe`, then continue with the rest. If many failures, the log prints the first 3 samples with `luid/index/metric` — paste that line to isolate |
| `route: route add ... failed: <text>` | Error from `route.exe`; more specific than WinAPI (unreachable gateway, invalid interface index, etc.) |

## Relationship with the eBPF transparent inbound

The eBPF inbound implements the same "destination CIDR bypass" idea at the
TC decision layer with `local.bypass-rule-set` / `shared.bypass-rule-set`
(naming aligned with sing-ebpf/sing-box upstream). The TUN inbound uses the
`route-exclude-*` family. Each handles its own traffic plane and both can be
enabled at the same time: eBPF covers local-host interception, TUN covers the
rest. See `ebpf-inbound.md` for the eBPF data planes.