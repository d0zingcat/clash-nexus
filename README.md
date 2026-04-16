# Clash to Loon Config Converter

将 Clash (mihomo) YAML 配置文件转换为 [Loon](https://nsloon.app) `.conf` 配置文件。

Go 实现，无需安装任何运行环境，直接下载二进制即可使用。

## 快速开始

### 直接编译使用

```bash
go build -o converter .
./converter input/clash.yaml -o output/loon.conf
```

也可以指定路径：

```bash
./converter path/to/clash.yaml -o path/to/output.conf
```

## 支持的转换

### 节点协议

| Clash | Loon |
|-------|------|
| trojan | trojan |
| ss | Shadowsocks |
| vmess | vmess |
| vless | VLESS |
| hysteria2 | Hysteria2 |

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
| `dns` | `[General]` dns-server/doh-server | DNS 配置 |
| `hosts` | `[Host]` | 域名映射 |

### 自动处理

- `RULE-SET` 规则自动转为 `[Remote Rule]`，blackmatrix7 的 URL 自动从 Clash 格式转为 Loon 格式
- `MATCH` 规则自动转为 `FINAL`
- `dialer-proxy` 节点自动生成 `[Proxy Chain]` 条目，策略组中的引用同步替换
- `proxy-providers` 的 `filter` 正则自动转为 `[Remote Filter]` 的 `NameRegex`
- 配置 SubStore 解析器以兼容各类订阅格式

## 目录结构

```
├── main.go          # 转换器源码（Go）
├── go.mod / go.sum  # Go 模块依赖
├── input/           # Clash 源配置（all-in-one.yaml 不纳入版本控制）
│   └── example.yaml # 脱敏示例配置
├── output/          # 生成的 Loon 配置（不纳入版本控制）
│   └── loon.conf
└── docs/            # 设计文档
```

## 不支持 / 需手动处理

- Clash 的 `tun`、`sniffer`、`experimental` 段（Loon 无对应）
- Loon 的 `[Rewrite]`、`[Script]`、`[Plugin]`、`[MITM]`（Clash 无源数据，需手动配置）
- ACL4SSR 等非 blackmatrix7 规则源的 URL 可能需要手动验证兼容性（输出中会有 `[NOTE]` 注释提示）

## 参考

- [Loon 手册](https://nsloon.app/docs/intro)
- [Clash (mihomo) 配置文档](https://wiki.metacubex.one/en/config/)
- [blackmatrix7 规则集](https://github.com/blackmatrix7/ios_rule_script)
