# Loon AnyTLS 节点格式修复

日期：2026-10-18

## 现象

Clash 订阅（含 AnyTLS 节点）转换为 Loon 配置后，所有 AnyTLS 节点都超时。Loon 日志中表现为：TLS 已经建立、认证帧已发出，随后连接被服务端静默关闭：

```
[AnyTLS][auth] node=AnyTLS key=password="57171617-...-1cbb1a986872" sha256=5d456b9c...
[AnyTLS][disconnect] node=AnyTLS seq=6 err=... "Socket closed by remote peer" status=5
```

策略组、规则匹配、DNS 都正常，只有节点握手失败，所以看什么都是 timeout。

## 根因

Loon 官方节点文档规定 AnyTLS 的密码是**协议必填的位置参数**：

```
节点名称 = AnyTLS,服务器,端口,"密码",可选参数
```

转换器之前输出的是 `key=value` 形式：

```
节点 = AnyTLS,host,443,password="<uuid>"
```

Loon 会把整个 `password="<uuid>"` token（连同 `password=` 前缀和引号）当作密码。
日志里的 `sha256` 就是证据：

| 密码候选 | SHA-256 |
| --- | --- |
| `<uuid>` | `dd2502b3...71c120` |
| `password="<uuid>"` | `5d456b9c...1f881` ← 与 Loon 日志一致 |

AnyTLS 服务端在密码校验失败时不会返回错误，而是直接关闭连接（避免泄露协议/状态信息），
于是客户端看到的就是 `Socket closed by remote peer`，随后所有请求超时。

## 修复

`converter/loon/loon.go`：

- AnyTLS 密码改为位置参数：`AnyTLS,server,port,"password"`。
- `client-fingerprint` 改为 Loon 文档中的 `tls-profile=`（原输出的 `client-fingerprint=` 键名 Loon 不认识），
  并把 Clash 取值映射到 Loon 支持的 `chrome` / `safari-ios18` / `safari-ios-26` / `default` / `global`，
  其他取值（`firefox`、`randomized` 等）直接省略，让 Loon 用默认 ClientHello 指纹。
- `alpn` 值按文档加双引号。
- 补齐 AnyTLS 的 Reality 参数（`public-key`、`short-id`）与 `udp=true`（Loon 默认不转发 UDP，
  缺省会丢失 QUIC/UDP 流量）。
- VLESS 输出的指纹键名同步由 `fingerprint=` 修正为 `tls-profile=`。

## 验证

```bash
go test ./...
go run . -target loon -input /tmp/anytls.yaml -o /tmp/anytls.loon.conf
# 🇯🇵 JP AnyTLS = AnyTLS,lno-jp.riot-cdn.latest10.org,443,"57171617-...",sni=...,skip-cert-verify=true,udp=true
```

原有的 AnyTLS、VLESS、WireGuard、DNS 相关测试全部通过，并新增了断言：输出中不得出现
`password=` 与 `client-fingerprint=`。
