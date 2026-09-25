# eBPF transparent inbound

This document covers the mihomo eBPF transparent inbound: the local cgroup/TC
data path and the optional shared-network TC (hotspot) data path. The feature
is enabled only in builds with the `with_ebpf` build tag on Linux or Android.
Other platforms compile with a stub that returns an explicit unsupported error.

The eBPF business layer is extracted into the `github.com/CHIZI-0618/sing-ebpf`
dependency. BPF objects ship pre-generated inside that module, so a mihomo
build needs no clang step; the backend is pure Go and builds with
`CGO_ENABLED=0`.

## Supported environments

- Operating systems: Linux, Android.
- Architectures built by CI: linux/amd64, linux/arm64, android/arm64.
- Make targets: `linux-amd64-ebpf`, `linux-arm64-ebpf`, plus any build with
  `-tags "with_gvisor with_ebpf"`.
- Kernel: cgroup v2 with BPF support. The loader detects required kernel
  features at runtime and uses compatibility paths when optional helpers are
  missing.

Required kernel features:

- cgroup/sockaddr program types: connect4/connect6, sendmsg4/6, recvmsg4/6.
- BPF maps: hash, lpm_trie, array, and prog_array as used by the loader.
- cgroup inet sock release attach and `BPF_MAP_LOOKUP_AND_DELETE_ELEM` are
  optional; when either is missing the loader uses a compatibility path.

## Capabilities and kernel configuration

The process must be privileged or hold the following effective capabilities:

- `CAP_BPF` or `CAP_SYS_ADMIN` for BPF syscalls and cgroup attach.
- `CAP_NET_ADMIN` for shared-network TC qdisc attachment and route/sysctl setup.
- `CAP_NET_RAW` for raw socket operations used by the data path.
- The ability to raise `RLIMIT_MEMLOCK` enough for configured BPF maps.

The kernel needs at least `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, and
`CONFIG_CGROUP_BPF`. `CONFIG_BPF_JIT` is strongly recommended for throughput.
The shared-network path additionally needs `CONFIG_NET_CLS_BPF`.

## Build

The eBPF build is a normal Go build with the `with_ebpf` tag; it does not
require a BPF cross-compiler:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags "with_gvisor with_ebpf" -o mihomo-ebpf .
```

Android ARM64 builds are covered by `.github/workflows/build-ebpf.yml`.

## Configuration

Add an `ebpf` listener to the `listeners` section:

```yaml
listeners:
  - name: ebpf-inbound
    type: ebpf
    # enablement: mode (local/shared/hybrid) OR explicit local.enable /
    # shared.enable. When enable is present, mode must be omitted.
    mode: local
    network: [tcp, udp]
    udp-timeout: 300
    tc-priority: 1
    bypass-rule-set:
      - geoip-cn
    local:
      enable: true
      data-plane: cgroup      # cgroup (default) or tc
      cgroup-path: ""         # absolute cgroup v2 path; empty = auto-detect
      dns-mode: hijack        # hijack (default), respect_policy, or off
      ipv6: true
      bypass-private-address: true
      include-uid: []
      include-uid-range: []
      exclude-uid: []
      exclude-uid-range: []
      include-android-user: []   # Android only
      include-package: []        # Android only
      exclude-package: []        # Android only
      bypass-port: []
      bypass-port-range: []
    shared:
      enable: false
      data-plane: packet_rewrite # packet_rewrite (default) or socket_assign
      interface: [wlan0]        # downstream interfaces (required when shared enabled)
      dns-mode: hijack
      ipv6: true
      bypass-private-address: true
      include-source-cidr: []
      exclude-source-cidr: []
      include-mac-address: []
      exclude-mac-address: []
      bypass-port: []
      bypass-port-range: []
```

Field behavior:

- `mode`: `local` (default), `shared`, or `hybrid`. Alternatively use
  `local.enable` / `shared.enable` as independent toggles; mode cannot be
  combined with them. `local.enable: true` enables only local interception,
  `shared.enable: true` enables only shared interception, both enable hybrid.
- `network`: `tcp`, `udp`, or both. Defaults to both when omitted.
- `local.data-plane`: `cgroup` (default) or `tc`. `cgroup` intercepts inner
  sockets connect()/sendmsg(); `tc` steers packets on the default interface.
- `local.cgroup-path`: absolute cgroup v2 directory for the cgroup data plane;
  requires `data-plane=cgroup`. Empty means auto-detect.
- `local.dns-mode` / `shared.dns-mode`: `hijack` (default), `respect_policy`,
  or `off`. `hijack` force-rewrites port 53; `off` always passes 53.
- `local.bypass-private-address`: private/groupcast/link-local destinations
  keep their real IP and pass in kernel. Default true.
- `shared.data-plane`: `packet_rewrite` (default) or `socket_assign`.
- `shared.interface`: the downstream interfaces to take over (hotspot). Must
  not be empty when shared is enabled, and must not contain `lo`.
- `bypass-rule-set`: rule provider tags whose internal CIDRs are published as
  pass decisions to every enabled data plane.
- `include-uid`, `include-uid-range`, `exclude-uid`, `exclude-uid-range`:
  UID-based interception policy. Ranges use `start:end` syntax.
- Android only: `include-android-user`, `include-package`, `exclude-package`.
- `bypass-port`, `bypass-port-range`: destination ports that bypass in kernel.

## IPv4 and IPv6 behavior

The internal TCP and UDP listeners are created with explicit address families
(`tcp4`, `tcp6`, `udp4`, `udp6`) and IPv6 listeners set `IPV6_V6ONLY`. The
cgroup/shared redirect prefixes are selected automatically (IPv4 default
`127.128.0.0/9`) and must not overlap routable local traffic. IPv6 interception
is enabled per `ipv6` when the host provides IPv6 connectivity.

## Android differences

Android uses the same cgroup v2 mechanism but the effective cgroup hierarchy
and permission model differ by vendor. The auto-detected cgroup path can be
overridden with `local.cgroup-path`. Package policy is resolved to Android UIDs
and `include-android-user` maps a user ID to its per-user UID range. The DNS
tethering UID is always excluded.

SELinux must permit BPF map/program creation, cgroup attach, and socket
operations for the mihomo domain. On restricted Android builds the feature is
usually only usable from a root or Magisk-provided service context.

## Containers

A container running the eBPF inbound needs:

- `/sys/fs/cgroup` mounted read-write and containing the target cgroup v2 hierarchy.
- `CAP_BPF` (or `CAP_SYS_ADMIN`) and `CAP_NET_ADMIN`.
- `RLIMIT_MEMLOCK` not blocked by the container runtime.
- No seccomp profile that filters `bpf`, `setsockopt`, `netlink`, or `tc`.

For shared-network TC mode the container also needs the downstream interface
inside its network namespace and the `net.ipv4.conf.<iface>.route_localnet`
sysctl set on that interface.

## Diagnostics

The startup log lists the active data planes, listener port, DNS modes, and
bypass CIDR counts. Interface updates drive a retry scheduler with per-component
backoff; transient attach/reconcile failures are recovered automatically.

- Verifier failure: the log includes the program name, errno, and verifier log.
  Check kernel config/helpers, map capacity, and `RLIMIT_MEMLOCK`.
- Permission denied: verify root or `CAP_BPF`/`CAP_SYS_ADMIN`/`CAP_NET_ADMIN`,
  seccomp, Android SELinux, and container device policy.
- Attach failed: verify the configured cgroup path is a cgroup v2 mount, is
  writable, and is not already attached by another instance.
- Port conflict: the internal listener set binds an ephemeral port shared
  across the enabled protocol/family listeners. Startup rolls back all
  listeners if any bind fails; check `ss -lntup` for the reported port.

## Shutdown and cleanup

`Close()` is idempotent. It stops UDP sweeps, detaches BPF links, closes map
and program file descriptors, closes the internal listeners, removes
shared-network TC attachments and local routes, and unregisters the socket
protect function. No BPF objects are pinned by the implementation, so stopping
mihomo leaves no persistent program or map names.

## Relationship with TUN, TProxy, and Redir

The eBPF inbound intercepts sockets inside the selected cgroup or interface; it
is not a full TUN device and does not route all host traffic by itself. It can
coexist with TUN, TProxy, and Redir, but avoid attaching multiple transparent
inbound mechanisms to the same cgroup or interface unless you intentionally
split traffic with UID, CIDR, and `bypass-rule-set` policies. The shared mode
uses TC on named downstream interfaces and can be used for hotspot forwarding
while the cgroup path handles local apps.
