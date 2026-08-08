# eBPF inbound port map

Source repository: `TanakaLun/mihomo`, branch `ebpf-inbound`.
Target baseline: `MetaCubeX/mihomo`, branch `Alpha`.
Deployed branch: `Alpha` (`ebpf-inbound` was merged into `Alpha` and the temporary branch was removed).

Baselines:

- Upstream: `Alpha` at `1af24e989c157dd506f0456b859e5bb5f3166bc1`
- Downstream before rebase: `ebpf-inbound` at `b1843ef975d23e73616d1610cbb47efb62d3214d`
- Downstream after rebase: `ebpf-inbound` at `d2937811` before the documentation/CI commits; merged into `Alpha`

## Migration decision

Only commits required for the cgroup eBPF transparent inbound were carried over.
The old merge commit `ce8b5906` was dropped and the branch was rebuilt linearly on
the current upstream `Alpha` baseline. The historical `component/ebpf`
implementation was not copied; this branch contains the current transparent
inbound implementation under `common/ebpf` and `listener/sing_ebpf`.

## Commit map

| Source commit | Target commit | Category | Status | Verification |
| --- | --- | --- | --- | --- |
| `1cf0a5be` | `8c13ec2e` | feature: cgroup eBPF inbound | Ported | config/unit tests, Linux and Android CI builds |
| `5ad3c0a5` | `d37a4a85` | fix: explicit listener address family | Ported | IPv4/IPv6 listener tests, Android build |
| `6952cce3` | `886a2860` | fix: lookup+delete fallback | Ported | map ABI tests, privileged integration tests |
| `eedaae64` | `a3063b2c` | feature: shared-network TC inbound | Ported | shared-network unit tests, TC generation check |
| `71ae3d01` | `5928b89d` | fix(ci): multiarch include path | Ported | `make ebpf_generate` and `make ebpf_check` in CI |
| `5bca0f45` | `76998d4b` | fix: hotspot bypass flags | Ported | shared-network policy tests |
| `4203f249` | `101756f6` | feature: Android package policy | Ported | Android UID tests, Android ARM64 build |
| `574af830` | `26a0286f` | fix(ci): Android ARM64 workflow | Ported | Android ARM64 build |
| `02906c9e` | `ef453a91` | chore: sing-tun redirect patch | Ported | Android ARM64 build with patch applied |
| `d74e236d` | `6c709dc7` | ci: fetch sing-tun patch | Ported | Android ARM64 build |
| `12c53535` | `4a1a0d30` | fix(ci): regenerate patch | Ported | Android ARM64 build |
| `8a59f031` | `1b0eda58` | feature: source-CIDR and IPv6 policy | Ported | config and shared-network tests |
| `97f315ba` | `280b4a7a` | feature: major inbound refactor | Ported | full test suite, Linux/Android builds |
| `b1843ef9` | `d2937811` | fix: UDP timeout propagation | Ported | UDP state tests, full test suite |

The merge commit `ce8b5906` is intentionally absent from the target history.
Upstream changes are applied through the linear rebase instead.

## Rejected commits

Historical eBPF commits that were removed upstream or are unrelated to the
current transparent inbound design were not migrated:

- `31f4d204 support ebpf`
- `bb413ece Merge pull request #144 from zhudan/ebpf`
- `97270dcb rm EBpf tun && disable android ebpf`
- `d3b88d1b fix: ebpf support`
- `0793998d chore: drop support of eBPF`

## Generated files

`common/ebpf/native/shared_network.bpf.o` is generated from
`common/ebpf/native/shared_network.bpf.c` and is intentionally not committed.
CI runs:

```bash
make ebpf_generate
make ebpf_check
```

`ebpf_check` fails when the checked-in source and generated object drift, so the
generated artifact remains traceable to its build command.
