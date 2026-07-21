# Clash Nexus

将 Clash (mihomo) YAML 配置文件转换为多种代理工具格式。

也支持以 Loon `.conf` 作为输入，转换为 Clash/Mihomo YAML、Egern 或 Quantumult X：

```bash
./clash-nexus -source loon -target clash input/loon.conf
./clash-nexus -source loon -target qx input/loon.conf
```

API、文件上传与订阅地址均可传入 `source=loon`。无法无损映射的 Loon 段或参数会以 warning 返回；例如脚本、复写、插件和未实现的传输参数不会静默丢弃。

Go 实现，无需安装任何运行环境，直接下载二进制即可使用。

## 快速开始

```bash
make build

# 转换为 Egern
./clash-nexus -target egern input/clash.yaml

# 转换为 Loon
./clash-nexus -target loon input/clash.yaml

# 转换为 Stash
./clash-nexus -target stash input/clash.yaml

# 指定输出路径
./clash-nexus -target loon -input input/clash.yaml -o output/custom.conf

# 启动本地网页和转换 API
make serve
```

启动后打开 `http://127.0.0.1:8080`，可以粘贴 YAML、上传文件或输入远程 Clash 配置 URL，选择目标格式后预览并下载转换结果。

## Web/API

### 本地网页

```bash
make install
make serve
```

默认只监听 `127.0.0.1`。网页使用 React + Tailwind + shadcn/ui 风格组件，`pnpm run web:build` 会把前端产物输出到 `internal/web/static/`，随后由 Go 二进制内置。

### Docker

```bash
make docker-build
make docker-run
```

容器默认监听 `0.0.0.0:8080`，访问 `http://127.0.0.1:8080`。

GitHub Actions 会在 `main` 分支和 `v*` tag 上构建并推送镜像到 GHCR：

```text
ghcr.io/<owner>/<repo>:latest
ghcr.io/<owner>/<repo>:sha-<commit>
ghcr.io/<owner>/<repo>:vX.Y.Z
```

### 转换接口

```bash
# 查看支持目标
curl http://127.0.0.1:8080/api/targets

# 通过粘贴 YAML 转换
curl -X POST http://127.0.0.1:8080/api/convert \
  -H 'Content-Type: application/json' \
  -d '{"target":"loon","yaml":"rules:\n  - MATCH,DIRECT\n"}'

# 通过远程 URL 转换
curl -X POST http://127.0.0.1:8080/api/convert \
  -H 'Content-Type: application/json' \
  -d '{"target":"egern","url":"https://example.com/clash.yaml"}'

# 可直接填入客户端的订阅转换地址
curl 'http://127.0.0.1:8080/api/subscribe?target=loon&url=https%3A%2F%2Fexample.com%2Fclash.yaml'

# 通过文件上传转换
curl -X POST http://127.0.0.1:8080/api/convert/file \
  -F target=loon \
  -F file=@input/example.yaml
```

远程 URL 第一版只允许 `http` / `https`，请求超时为 10 秒，输入大小限制为 5 MiB。

## 支持的转换目标

| 目标 | 格式 | 默认输出路径 |
|------|------|------------|
| `loon` (默认) | `.conf` (INI-like) | `output/loon.conf` |
| `egern` | `.yaml` | `output/egern.yaml` |
| `stash` | `.yaml` | `output/stash.yaml` |

## Loon 转换

### 节点协议

| Clash | Loon |
|-------|------|
| trojan | trojan |
| ss | Shadowsocks |
| vmess | vmess |
| vless | VLESS |
| hysteria2 | Hysteria2 |
| wireguard | WireGuard |
| anytls | AnyTLS |

### 配置段落映射

| Clash | Loon | 说明 |
|-------|------|------|
| `proxies` | `[Proxy]` | 本地节点 |
| `proxy-providers` | `[Remote Proxy]` | 远程订阅 |
| `proxy-groups` (use + filter) | `[Remote Filter]` | 节点筛选器 |
| `proxy-groups` | `[Proxy Group]` | 策略组 (select/url-test/fallback/load-balance) |
| `dialer-proxy` | `[Proxy Chain]` | 代理链 |
| `rules` | `[Rule]` | 本地规则 |
| `rule-providers` | `[Remote Rule]` | 远程规则订阅 |
| `dns` | `[General]` dns-server/doh-server/doq-server/doh3-server | DNS 配置 |
| `hosts` | `[Host]` | 域名映射 |

### 自动处理

- `RULE-SET` 规则自动转为 `[Remote Rule]`，blackmatrix7 的 URL 自动从 Clash 格式转为 Loon 格式
- `MATCH` 规则自动转为 `FINAL`
- `dialer-proxy` 节点自动生成 `[Proxy Chain]` 条目，策略组中的引用同步替换
- `proxy-providers` 的 `filter` 正则自动转为 `[Remote Filter]` 的 `NameRegex`
- 配置 SubStore 解析器以兼容各类订阅格式
- 转换时自动拉取每个 `proxy-providers` 的订阅 URL，校验内容是否为**通用节点格式**（见下文注意事项）

## Egern 转换

### 节点协议

| Clash | Egern | 说明 |
|-------|-------|------|
| trojan | trojan | ✅ |
| ss | shadowsocks | ✅ |
| vmess | vmess | ✅，支持 ws/wss/h2/http/tls/reality transport |
| vless | vless | ✅，支持 ws/wss/h2/http/tls/reality transport |
| hysteria2 | hysteria2 | ✅ |
| socks5 | socks5 | ✅ |
| http | http | ✅ |
| **ssr** | — | ❌ **不支持**，转换时输出 `[WARNING]` 并跳过 |
| tuic / wireguard 等 | — | ❌ **不支持**，转换时输出 `[WARNING]` 并跳过 |

> 跳过的节点会在 stderr 输出警告，例如：
> ```
> [WARNING] skipping proxy "my-ssr-node" (type: ssr) — not supported by Egern
> ```

### 配置映射

| Clash | Egern | 说明 |
|-------|-------|------|
| `proxies` | `proxies` | 本地节点 |
| `proxy-providers` (use 引用) | `policy_groups[].external` | 外部订阅策略组 |
| `proxy-groups` (select) | `policy_groups[].select` | 手动选择策略组 |
| `proxy-groups` (url-test) | `policy_groups[].auto_test` | 自动测速策略组 |
| `proxy-groups` (load-balance) | `policy_groups[].load_balance` | 负载均衡策略组 |
| `dialer-proxy` | `prev_hop` | 节点上的代理链字段 |
| `mixed-port` | `http_port` | Egern 无混合端口；不会同时写入 `socks_port` |
| `port` / `socks-port` | `http_port` / `socks_port` | 仅在 Clash 明确分开配置时分别映射 |
| `rules` | `rules` | 路由规则 |
| `rule-providers` (RULE-SET) | `rules[].rule_set` | 规则集，blackmatrix7 的 Clash URL 自动转为 Surge URL |
| `MATCH`/`FINAL` | `rules[].default` | 默认策略 |
| `dns.default-nameserver` | `dns.bootstrap` | 用于解析 DoH 域名的 UDP DNS |
| `dns.nameserver` | `dns.upstreams.default` | 默认 DNS 上游 |
| `dns.fallback` (DoH/DoT/DoQ) | `dns.upstreams.doh/dot/doq` | 加密 DNS 上游 |
| `dns.fake-ip-filter` | `real_ip_domains` | Real IP 域名（`*` 被过滤，`+.` 转为 `*.`） |
| `hosts` | `dns.hosts` | 静态域名映射 |

## 注意事项

### proxy-providers 订阅链接须为通用节点格式（Loon）

`proxy-providers` 的 `url` 必须指向**通用节点订阅**，即返回以下两种内容之一：

- **Base64 编码的代理 URI 列表**：每行一条节点链接（`ss://`、`vless://`、`trojan://`、`vmess://` 等）经 Base64 整体编码
- **仅含 `proxies:` 字段的 YAML**：不含 `rules`、`proxy-groups`、`dns` 等完整客户端配置字段

**❌ 不要使用**针对特定代理软件生成的完整配置链接，例如：

```
# 错误：Clash 专属订阅链接
https://example.com/subscribe?token=xxx&clash=1
https://example.com/subscribe?token=xxx&flag=clash
```

转换时若检测到订阅内容不合规，输出文件中会在对应条目上方输出 `# [WARNING]` 提示。

### Egern 的 rule-providers 使用 Surge 规则集

blackmatrix7 仓库没有 `rule/Egern` 目录。Egern 官方 FAQ 说明目前支持 Surge rule set，因此转换 blackmatrix7 的 `rule/Clash/.../*.yaml` 时会自动改写为 `rule/Surge/.../*.list`。

### 不支持 / 需手动处理

**Loon：**
- Clash 的 `tun`、`sniffer`、`experimental` 段（Loon 无对应）
- Loon 的 `[Rewrite]`、`[Script]`、`[Plugin]`、`[MITM]`（需手动配置）
- ACL4SSR 等非 blackmatrix7 规则源的 URL 可能需验证兼容性（输出中有 `[NOTE]` 注释）

**Egern：**
- SSR 节点：Egern 不支持，转换时跳过并输出 stderr 警告
- tuic、wireguard 等协议：同上
- 非 blackmatrix7 的 Clash 格式远程规则集：需自行确认 Egern 是否支持，必要时替换为 Surge 规则集
- Clash 的 `tun`、`sniffer` 段（Egern 侧自行配置）

**Stash：**
- 移除 Mihomo 的入站、`tun`、`sniffer` 配置
- 无法映射的 DNS 字段会移除；Tailscale 节点仅保留 Stash 已文档字段
- 上述移除或字段裁剪均会返回 warning

## 目录结构

```
├── main.go                    # CLI 入口（-target 选择转换目标）
├── converter/
│   ├── converter.go           # Converter 接口定义
│   ├── clash/util.go          # 共享工具函数
│   ├── loon/loon.go           # Loon 转换器
│   └── egern/egern.go         # Egern 转换器
├── go.mod / go.sum
├── input/                     # Clash 源配置（真实配置不纳入版本控制）
│   └── example.yaml           # 脱敏示例配置
├── output/                    # 生成的配置（不纳入版本控制）
│   ├── loon.conf
│   └── egern.yaml
└── docs/                      # 设计文档
```

## 扩展：新增转换目标

1. 创建 `converter/<name>/<name>.go`，实现 `Converter` 接口（`Name`、`DefaultExtension`、`Convert`）
2. 在 `main.go` 的 `registry` map 中注册，其他无需改动

## 参考

- [Egern 文档](https://egernapp.com/docs/intro)
- [Loon 手册](https://nsloon.app/docs/intro)
- [Clash (mihomo) 配置文档](https://wiki.metacubex.one/en/config/)
- [blackmatrix7 规则集](https://github.com/blackmatrix7/ios_rule_script)
