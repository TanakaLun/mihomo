# Mihomo Web API 文档 (GUI 接入参考)

Base URL: `http://{{controller-address}}`(由 `external-controller` 配置,默认 `127.0.0.1:9090`)

认证:若配置了 `secret`,请求需携带请求头 `Authorization: Bearer {{secret}}`

响应格式:`application/json`

统一错误格式:
```json
{ "message": "错误描述" }
```

---

## 目录

- [约定](#约定)
- [系统信息](#系统信息)
- [实时流量](#实时流量)
- [流量记录 (traffic-records)](#流量记录traffic-records)
- [日志](#日志)
- [配置](#配置)
- [代理](#代理)
- [代理组](#代理组)
- [规则](#规则)
- [连接](#连接)
- [提供者](#提供者)
- [DNS](#dns)
- [缓存](#缓存)
- [存储](#存储)
- [升级 / 重启](#升级--重启)

---

## 约定

| 方法 | 说明 |
|---|---|
| `GET` | 查询 |
| `PUT` / `PATCH` | 修改 |
| `POST` | 触发动作 |
| `DELETE` | 删除 |

流式接口(`/traffic`、`/logs`、`/connections`、`/memory`)同时支持 SSE 与 WebSocket 升级,每行一个 JSON。

错误状态码:

| 状态码 | 含义 |
|---|---|
| 400 | 请求体无效 |
| 401 | 未认证 |
| 403 | 禁止访问 |
| 404 | 资源不存在 / 功能未开启 |
| 504 | 超时 |

---

## 系统信息

### `GET /`

健康检查。

```json
{ "hello": "mihomo" }
```

### `GET /version`

```json
{ "meta": true, "version": "1.18.6" }
```

---

## 实时流量

### `GET /traffic` (SSE / WebSocket)

每秒一个 JSON 对象。

```json
{
  "up": 1234,
  "down": 5678,
  "upTotal": 99999,
  "downTotal": 88888,
  "upCumulative": 11111,
  "downCumulative": 22222
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `up` / `down` | int64 | 瞬时时速(字节/秒) |
| `upTotal` / `downTotal` | int64 | 本次进程启动以来的累计(字节) |
| `upCumulative` / `downCumulative` | int64 | 跨重启累积总量(需开启 `traffic-records.cumulative.enable`,否则为 0) |

### `GET /memory` — SSE

```json
{ "inuse": 12345678, "oslimit": 0 }
```

---

## 流量记录 (traffic-records)

> 关联配置:`traffic-records` 块。所有查询接口均为普通 REST(非流式),适合 GUI 按需拉取。

### `GET /traffic/cumulative`

查询累积流量(跨重启)。未开启返回 `404`。

```json
{ "upCumulative": 11111, "downCumulative": 22222 }
```

### `DELETE /traffic/cumulative`

重置累积流量(内存计数并立即落盘为 0)。未开启返回 `404`。

响应:`204 No Content`

### `GET /traffic/destinations`

查询各 (目标, 进程) 的访问次数与总流量聚合表。未开启返回 `404`。

查询参数(均可选):

| 参数 | 说明 |
|---|---|
| `sort` | 排序字段:`host`(默认)、`upload`、`download`、`count`、`lastSeen` |
| `order` | `asc`(默认) / `desc` |
| `host` | 按目标(域名/IP)包含匹配过滤 |
| `limit` | 返回条数上限 |
| `offset` | 分页偏移 |

响应:

```json
{
  "destinations": [
    {
      "host": "example.com",
      "process": "com.android.chrome",
      "visitCount": 120,
      "uploadTotal": 3421772800,
      "downloadTotal": 8589934592,
      "lastSeen": "2026-08-08T10:00:00.123Z"
    }
  ],
  "total": 42
}
```

| 字段 | 说明 |
|---|---|
| `host` | 目标:域名(Host)或 IP(无域名时) |
| `process` | 进程名(需开启 `find-process-mode` 才会填充,否则为空) |
| `visitCount` | 该(目标, 进程)经由核心接管的连接次数 |
| `uploadTotal` / `downloadTotal` | 字节数 |
| `lastSeen` | 最近一次连接关闭时间 |
| `total` | 过滤后总条数(未截断) |

### `DELETE /traffic/destinations`

清空目标聚合表(内存 + 持久化)。未开启返回 `404`。

响应:`204 No Content`

---

## 日志

### `GET /logs` — SSE

查询参数:`level=info|warning|error|debug`(默认 `info`)、`format=structured`。

每行 JSON:

```json
{ "type": "info", "payload": "log message" }
```

结构化格式:

```json
{ "time": "15:04:05", "level": "info", "message": "log message", "fields": [] }
```

---

## 配置

### `GET /configs`

当前运行配置,含 `traffic-records` 开关状态:

```json
{
  "port": 7890,
  "socks-port": 7891,
  "mixed-port": 0,
  "allow-lan": false,
  "mode": "rule",
  "ipv6": true,
  "log-level": "info",
  "traffic-records": {
    "cumulative": false,
    "destination": true
  }
}
```

### `PUT /configs`

整体重载配置(embed 模式下禁用)。

请求体(二选一):

```json
{ "path": "/绝对/路径/config.yaml" }
```

```json
{ "path": "", "payload": "port: 7890\n..." }
```

响应:`204 No Content`

### `PATCH /configs`

部分热更新。可提交任意子集字段:

```json
{
  "port": 7891,
  "allow-lan": true,
  "mode": "global",
  "traffic-records": {
    "cumulative": true,
    "destination": false
  }
}
```

- `traffic-records.cumulative` / `traffic-records.destination` 省略则保持原状态。

响应:`204 No Content`

---

## 代理

### `GET /proxies`

### `GET /proxies/{name}`

### `PUT /proxies/{name}`

在 Selector 组中选择节点。

```json
{ "name": "node-name" }
```

### `DELETE /proxies/{name}`

取消固定选择(恢复自动选择)。

### `GET /proxies/{name}/delay`

参数:`url`(必)、`timeout`(毫秒,必)、`expected`(如 `200,300-399`)。

```json
{ "delay": 123 }
```

---

## 代理组

### `GET /group`

### `GET /group/{name}`

### `GET /group/{name}/delay`

参数同个延迟测试。响应为 `{ "节点名": 延迟ms, ... }`。

---

## 规则

### `GET /rules`

```json
{
  "rules": [
    {
      "index": 0,
      "type": "Domain",
      "payload": "example.com",
      "proxy": "Proxy",
      "size": -1,
      "extra": { "hitCount": 0, "hitAt": "...", "missCount": 0, "missAt": "..." }
    }
  ]
}
```

### `PATCH /rules/disable` — 启用/禁用规则

```json
{ "0": true, "3": false }
```

---

## 连接

### `GET /connections`

```json
{
  "downloadTotal": 123456,
  "uploadTotal": 789012,
  "memory": 0,
  "connections": [
    {
      "id": "uuid",
      "metadata": { "network": "tcp", "type": "Socks5", "host": "example.com", "destinationPort": "443", ... },
      "upload": 1024,
      "download": 2048,
      "start": "...",
      "chains": ["Proxy"],
      "providerChains": [],
      "rule": "Domain",
      "rulePayload": "example.com"
    }
  ]
}
```

也支持 WebSocket 轮询(`?interval=500`)。

### `DELETE /connections` — 断开所有连接

### `DELETE /connections/{id}` — 断开指定连接

---

## 提供方

| 端点 | 说明 |
|---|---|
| `GET /providers/proxies` | 所有代理提供方 |
| `GET /providers/proxies/{providerName}` | 单个代理提供方 |
| `PUT /providers/proxies/{providerName}` | 强制刷新 |
| `GET /providers/proxies/{providerName}/healthcheck` | 触发健康检查 |
| `GET /providers/proxies/{providerName}/{name}` | 提供方内单个代理 |
| `GET /providers/proxies/{providerName}/{name}/healthcheck` | 提供方内单代理延迟测试(delay 参数同上) |
| `GET /providers/rules` | 规则提供方 |
| `PUT /providers/rules/{name}` | 强制刷新规则提供方 |

---

## DNS

### `GET /dns/query?name=example.com&type=A`

标准 DNS 应答 JSON:

```json
{
  "Status": 0,
  "Question": [{ "name": "example.com.", "qtype": 1, "qclass": 1 }],
  "Answer": [{ "name": "example.com.", "type": 1, "TTL": 300, "data": "1.2.3.4" }]
}
```

---

## 缓存

| 端点 | 说明 |
|---|---|
| `POST /cache/fakeip/flush` | 清空 fake-ip 池 |
| `POST /cache/dns/flush` | 清空 DNS 缓存 |

---

## 存储

| 端点 | 说明 |
|---|---|
| `GET /storage/{key}` | 读取 key 对应 JSON(不存在返回 `null`) |
| `PUT /storage/{key}` | 写入任意 JSON(上限 1MB) |
| `DELETE /storage/{key}` | 删除 key |

---

## 升级 / 重启

| 端点 | 说明 |
|---|---|
| `POST /upgrade` | 升级核心(`?channel=alpha&force=true`) |
| `POST /upgrade/geo` | 更新 geo 数据 |
| `POST /upgrade/ui` | 更新外部 Web UI |
| `POST /restart` | 重启进程 |

> `POST /restart`、`PUT/PATCH /configs`、`POST /upgrade` 在 embed 模式下禁用。

---

## 新增:流量记录行为说明

- 累积流量(`cumulative`):启动时从数据库读入,运行中每 `save-interval` 秒自动落盘,退出时再 flush 一次。`GET /traffic` 流中的 `upCumulative/downCumulative` 即该值。
- 目标聚合(`destination`):每个被核心接管并已关闭的连接,在关闭时按其 `(host/IP, process)` 聚合 `visitCount+1`、累加上行/下行,并更新 `lastSeen`。`max-records <= 0` 时为无上限存档;否则按 `lastSeen` 淘汰最旧条目。
- 上述两个开关通过 `PATCH /configs` 的 `traffic-records` 字段即可热切换,无需重启。