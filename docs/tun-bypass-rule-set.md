# TUN 内核级 CIDR 旁路（route-exclude-address-set / route-exclude-address）

让**目的 CIDR 命中 `route-exclude-address-set` 规则集或 `route-exclude-address`
静态 CIDR 的流量**在**内核层面绕过 TUN 设备**，不进入 mihomo 用户态，从而实现
接近裸机的直连性能。它是对 eBPF 透明入站（`ebpf-inbound.md`）中
`bypass-rule-set` 语义的 TUN 化移植，并统一收敛到 sing-tun 原生的
`route-exclude-*` 配置族：

- 所有平台：TUN 把规则集内的 CIDR 发布到共享的 **component/bypass** 注册表，
  DNS fake-ip 中间件对命中集合的域名回**真实 IP**（而不是 fake-ip），让旁路能
  真正生效；
- Windows：另外在**物理接口**上安装对这些 CIDR 的**更具体路由**（next hop 取自
  当前最优物理路由），匹配流量按最长前缀直接走物理网卡，**从不进入 TUN**（连
  wintun 环形缓冲和用户态协议栈都不经过，收益大于 eBPF 旁路）。

> `route-exclude-address-set`（规则集驱动、可热更新）与 `route-exclude-address`
> （静态 CIDR）是同一旁路管线的两个来源：静态段在 TUN 启动即发布，规则集段在
> 加载/热更新时发布。两者可以同时配置、叠加生效。

## 平台支持

| 能力 | Linux / Android | Windows | macOS |
|---|---|---|---|
| fake-ip → 真实 IP 联动（DNS） | ✅（TUN 与 eBPF 都发布） | ✅ | ✅ |
| 内核级路由旁路（不进 TUN） | 走 nftables/HW 方案，TUN 侧默认无 | ✅（本特性） | ❌（暂无路由 reconcile） |
| 需要管理员权限 | — | ✅（路由修改 + wintun） | — |

> eBPF 入站自身的内核旁路（cgroup/TC 的 `DecisionPass`）不受本页影响；本页描述
> 的是 **TUN** 入站的旁路能力，二者可共存（eBPF 处理本机，TUN 处理其它流量）。
> eBPF 入站侧保留 `local.bypass-rule-set` / `shared.bypass-rule-set` 命名（对齐
> sing-ebpf/sing-box 上游）；仅 TUN 侧统一使用 `route-exclude-*` 词表。

## 配置

```yaml
tun:
  enable: true
  stack: mixed
  dns-hijack:
    - any:53
  auto-route: true          # ❗ 建议开启：没有 auto-route 时 TUN 不接管默认路由，
                            #   Windows 旁路路由也会失去意义
  # strict-route: true      # 可选；目前 WFP 过滤器不阻断旁路流量，可共存

  route-exclude-address-set:  # 规则集 tag；命中集合的目的 CIDR 在内核旁路
    - geoip-cn              # 要求 behavior: ipcidr（整体提取）或
                            # behavior: classical（提取其中的 IP-CIDR 规则）
    # - geoip-lan
  route-exclude-address:      # （可选）静态 CIDR 直连，无需规则集，与上面叠加
    - 100.64.0.0/10           # 例如让 Tailscale tailnet 走物理网卡
  # route-address:            # 覆盖默认路由表（避免与旁路路由“一样宽”的前缀）
  #   - 0.0.0.0/1
  #   - 128.0.0.0/1

rule-providers:
  geoip-cn:
    type: http
    behavior: ipcidr        # ipcidr / classical 均可被 route-exclude-address-set 使用
    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geoip/cn.txt"
    path: ./ruleset/geoip-cn.txt
    interval: 86400

dns:
  enable: true
  enhanced-mode: fake-ip    # fake-ip 下会自动做 DNS 联动；redir-host 天然生效
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
```

> 迁移说明：旧版 `bypass-rule-set` / `bypass-address` 已合并进
> `route-exclude-address-set` / `route-exclude-address`，二者语义与效果完全一致
> （后者还额外获得 sing-tun 原生排除）。直接把配置里的 key 改名即可。

## 工作方式（Windows）

1. **发布**：TUN 入站启动/规则集热更新时，把 `route-exclude-address-set` 中所有
   规则集的 CIDR 与静态 `route-exclude-address` 求并集（`netipx.IPSet` 自动合并
   相邻段），发布到 `component/bypass`；关闭 TUN 时移除自己发布的部分（引用计数，
   不残留）。
2. **DNS 联动**：fake-ip 中间件看到有旁路集合时，对 A/AAAA 先做真实解析；答案落
   在集合内就返回真实 IP，让连接的目的地址能命中旁路路由（而非 fake-ip 段）。
   已建立 fake 映射的主机直接返回 fake 地址，不重复真实解析。
3. **路由安装**：对每个旁路前缀，在路由表里找一条**完整覆盖它**的物理路由
   （排除 TUN 接口；选最长前缀、同长取低 metric），把这条路由的
   `prefix + next hop + interface LUID + metric` 复制成一条**更具体的物理路由**
   安装下去。由于最长前缀匹配，这些流量不再匹配 TUN 的默认路由。
4. **热更新**：规则集更新时做差量（先加后删）；网络变化（Wi-Fi/有线/VPN 切换）
   时重新选择 next hop 并重建；打开 mihomo 时清掉自己安装的路由。

## 语义与边界（重要）

- **pass = 完全不进 TUN**：命中集合的流量由内核直达物理网卡，规则也不会看到它。
  这与 eBPF 的 `DecisionPass` 语义一致 —— 集合内的 CIDR 应是你"永远直连"的目标。
- **只支持目的 CIDR 维度**：`bypass-port`、进程/UID 维度在 Windows 路由层无法
  表达，那些流量仍走 TUN（无内核收益）。
- **比 TUN 覆盖路由更宽的前缀会被跳过**（安全回退到 TUN 内代理）：例如
  `route-exclude-address-set` 里出现 `0.0.0.0/0`、`0.0.0.0/1` 之类不会安装物理路由。
- **没有可用物理路由覆盖的前缀会被跳过**：例如目标只在 TUN 自己的 on-link
  网段内；此时流量仍进 TUN 被代理，属安全方向。
- **保护前缀不旁路**：TUN 自身地址段、`loopback-address` 永远不会被旁路。
- **fake-ip 注意**：不要把 fake-ip 段（默认 `198.18.0.0/16`）写进旁路集合；
  Windows 侧当前只防御 TUN 自身地址，geoip 类集合不会产生这种重叠。
- 已建立的连接不受新路由影响（路由只作用于新建连接）。

## 验证（Windows）

```powershell
# 1) 查看旁路路由是否落在物理网卡（非 Meta/TUN）
Get-NetRoute -DestinationPrefix 1.0.0.0/24

# 2) 用真实 IP 直连测试（域名命中集合时应回真实 IP）
curl.exe --resolve www.example.com:443:1.2.3.4 https://www.example.com/

# 3) 热更新规则集后复查路由增删
# 4) 关闭 mihomo 后确认旁路路由已全部消失
Get-NetRoute | Where-Object { $_.InterfaceAlias -ne "Meta" -and $_.RouteMetric -eq 0 } | Select-Object DestinationPrefix, NextHop, InterfaceAlias
```

FAQ：

- **需要管理员吗？** 需要（与 wintun + 改写路由表同一权限等级）。
- **为什么看 Get-NetRoute 里旁路前缀的 metric 和物理默认路由一样？**
  这是刻意的：复制原最优物理路由的 metric，多个等宽物理路径（如家里
  Wi-Fi + VPN）存在时，等价前缀选路由 Windows 自行裁决，保持"原来怎么走还怎么走"。
- **为什么没看到路由？** 规则集还没加载完 / 前缀比 TUN 路由宽 / 无物理覆盖路由
  / `auto-route` 未开启。日志里会有 Warn。
- **和 eBPF 入站的 `bypass-rule-set` 有什么区别？** eBPF 是另一个入站（TC 决策
  层），命名对齐 sing-ebpf 上游；TUN 侧统一为 `route-exclude-*`。两者各管各的
  流量，可共存。

## 排障（不生效时按顺序查）

用这套决策树在三分钟内定位：

1. **看日志确认发布**：启动/规则集更新后应有
   `[TUN] bypass-rule-set: N CIDRs published (1.0.1.0/24, ...)`。
   - N=0：`CN_IP` 规则集未加载完成或 behavior 不是 ipcidr/classical（日志有 Warn）。
2. **看旁路路由是否真的装上**（取日志里任意一个前缀，如集合里的 `1.0.1.0/24`）：
   ```powershell
   Get-NetRoute -DestinationPrefix 1.0.1.0/24 | fl DestinationPrefix, InterfaceAlias, NextHop, RouteMetric
   ```
   - 有且 `InterfaceAlias` 是物理网卡（不是 Meta）→ 路由 OK，跳到第 4 步。
   - 没有 → 日志应有 `apply bypass routes:` Warn（常见：TUN 接口 LUID 未解析到 /
     前缀被保护段覆盖 / 权限不足）。把这条 Warn 完整贴出来。
3. **确认流量确实没进 mihomo**：打开 mihomo → Connections，直连一个集合内的 IP；
   连接**不出现** = 绕过成功；出现 = 没绕过。
4. **域名测试必须走真实 IP**：
   - `enhanced-mode: redir-host`：天然真实 IP，直接可用。
   - `enhanced-mode: fake-ip`：DNS 联动生效的前提是旁路集合**先于**域名首次查询
     发布。若规则集加载晚于首次查询，旧 fake 映射会让域名继续走 TUN——用
     `curl --resolve <域名>:443:<真实IP> https://<域名>/` 验证真实 IP 路径，或
     `dns.flush-fake-ip`（API）清掉旧映射后再测。
5. **纯 IP 测试**（绕开 DNS，最快定位路由层）：
   ```powershell
   # 用集合内任意 IP，-S 指定本机物理网卡 IP
   Test-NetConnection 1.2.3.4 -InformationLevel Detailed
   ```

### 常见失败日志

| 日志 | 含义 / 处理 |
|---|---|
| `republished N CIDRs (...)` | 集合已发布（N 应为几千）；若为 0 查规则集加载 |
| `apply bypass routes: route: tun interface "meta" not found yet` | 启动早期 TUN 还没就绪，稍后自动重试，可忽略 |
| `CreateIpForwardEntry2 <prefix> via <gw> failed: Element not found` | WinAPI 添加失败；新版会重试 1 次并转用 `route.exe` 兜底，随后继续安装其余前缀。若仍大量失败，日志会打印带 `luid/index/metric` 的前 3 条样本，把该行发出来即可定位 |
| `route: route add ... failed: <文本>` | `route.exe` 的报错，文本比 WinAPI 更具体（如网关不可达、接口索引无效） |
