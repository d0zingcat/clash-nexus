---
title: "feat: Clash 配置转换为 Loon 配置"
type: feat
status: active
date: 2026-04-14
---

# feat: Clash 配置转换为 Loon 配置

## Overview

编写一个 Python 脚本，将现有的 Clash (mihomo) YAML 配置文件解析并转换为 Loon `.conf` 格式的配置文件。两者的配置模型高度相似（节点、策略组、规则、DNS），但语法格式完全不同——Clash 使用 YAML，Loon 使用 INI 风格的分段纯文本。

## Problem Frame

当前有一份完整的 Clash `all-in-one.yaml` 配置，包含自建节点、订阅源、策略组、规则集和 DNS 设置。需要在 iOS 上使用 Loon 客户端，但手动逐条转写配置既繁琐又容易出错。需要一个自动化转换工具。

## Requirements Trace

- R1. 解析 Clash YAML 配置中的所有主要段落
- R2. 将 `proxies` 转换为 Loon `[Proxy]` 段的节点格式
- R3. 将 `proxy-providers` 转换为 Loon `[Remote Proxy]` 段的订阅格式
- R4. 将 `proxy-groups` 转换为 Loon `[Proxy Group]` 段，包括 select / url-test / fallback / load-balance 类型，并正确处理 `use`（引用 provider）和 `filter` 的映射
- R5. 将 `rules` 转换为 Loon `[Rule]` 段，保持规则类型和策略映射
- R6. 将 `rule-providers` 转换为 Loon `[Remote Rule]` 段的订阅规则格式
- R7. 将 `dns` 配置转换为 Loon `[General]` 中的 dns-server / doh-server 以及 `[Host]` 段
- R8. 将 `hosts` 转换为 Loon `[Host]` 段
- R9. 生成合理的 `[General]` 段默认配置
- R10. 将 Clash 中使用 `dialer-proxy` 的节点转换为 Loon 的 `[Proxy Chain]` 段
- R11. 输出的 `.conf` 文件可直接导入 Loon 使用

## Scope Boundaries

- 不处理 Clash 的 `tun`、`sniffer`、`experimental` 等 Loon 无对应概念的段落
- 不处理 Loon 的 `[Rewrite]`、`[Script]`、`[Plugin]`、`[MITM]` 段（Clash 无对应源数据）
- 不做 GUI，仅 CLI 脚本
- rule-providers 中 `behavior: classical` 的 Clash 规则集 URL 需要替换为 Loon 兼容的规则集 URL（blackmatrix7 同时提供 Clash 和 Loon 格式）

### Deferred to Separate Tasks

- Loon 插件 / 复写 / 脚本配置：无 Clash 源数据，需单独手写
- 双向转换（Loon -> Clash）：未来迭代

## Context & Research

### Clash 配置结构（YAML）

| Clash 段 | 说明 |
|---|---|
| `proxies` | 节点列表，每个节点是一个 YAML 对象 |
| `proxy-providers` | 远程订阅源，含 URL、过滤器、健康检查 |
| `proxy-groups` | 策略组，支持 select/url-test/fallback/load-balance/relay |
| `rules` | 规则列表，格式 `TYPE,VALUE,POLICY` |
| `rule-providers` | 远程规则集，含 URL、behavior、interval |
| `dns` | DNS 配置，含 nameserver/fallback/fake-ip 等 |
| `hosts` | 域名映射 |

### Loon 配置结构（INI 风格）

| Loon 段 | 说明 |
|---|---|
| `[General]` | 通用设置，含 dns-server、doh-server、ip-mode 等 |
| `[Proxy]` | 本地节点，格式 `名称 = 协议,地址,端口,参数...` |
| `[Remote Proxy]` | 远程订阅，格式 `别名 = URL` |
| `[Remote Filter]` | 节点筛选器，支持 NameRegex 等 |
| `[Proxy Group]` | 策略组，格式 `名称 = 类型,节点/筛选器,参数...` |
| `[Proxy Chain]` | 代理链，格式 `名称 = 节点/策略组1, 节点/策略组2, udp=true` |
| `[Rule]` | 本地规则，格式 `TYPE,VALUE,POLICY` |
| `[Remote Rule]` | 远程规则订阅，格式 `URL,policy=POLICY` |
| `[Host]` | DNS 映射 |
| `[Rewrite]` | URL 重写 |
| `[Script]` | 脚本 |
| `[Plugin]` | 插件 |
| `[MITM]` | HTTPS 解密 |

### 关键映射关系

#### 节点协议映射

| Clash type | Loon 协议名 |
|---|---|
| `ss` | `Shadowsocks` |
| `ssr` | `ShadowsocksR` |
| `vmess` | `vmess` |
| `vless` | `VLESS` |
| `trojan` | `trojan` |
| `http` | `http` / `https` |
| `socks5` | `socks5` |
| `wireguard` | `wireguard` |
| `hysteria2` | `Hysteria2` |

#### 策略组类型映射

| Clash type | Loon type |
|---|---|
| `select` | `select` |
| `url-test` | `url-test` |
| `fallback` | `fallback` |
| `load-balance` | `load-balance` |
| `relay` | `[Proxy Chain]` 段 |

#### dialer-proxy 到 Proxy Chain 的映射

Clash 的 `dialer-proxy` 机制：节点 A 设置 `dialer-proxy: B`，表示 A 的流量先经过 B 再出去，形成链式代理。

Loon 的 `[Proxy Chain]` 段：`链名 = 入口节点/策略组, 出口节点/策略组, udp=true`

转换逻辑：
1. 扫描所有 `proxies`，找出设置了 `dialer-proxy` 的节点
2. 对于每个这样的节点（如 `A`，dialer-proxy 为 `B`），生成一条 Proxy Chain：`A (Chain) = A, B, udp=true`
   - 注意：Loon Proxy Chain 的顺序是「入口在前，出口在后」，即流量先到入口节点，再经由出口节点转发
3. 在 `[Proxy Group]` 中引用这些 Proxy Chain 名称替代原始节点名

#### 规则类型映射

| Clash 规则 | Loon 规则 | 备注 |
|---|---|---|
| `DOMAIN` | `DOMAIN` | 完全一致 |
| `DOMAIN-SUFFIX` | `DOMAIN-SUFFIX` | 完全一致 |
| `DOMAIN-KEYWORD` | `DOMAIN-KEYWORD` | 完全一致 |
| `IP-CIDR` | `IP-CIDR` | 完全一致 |
| `IP-CIDR6` | `IP-CIDR6` | 完全一致 |
| `GEOIP` | `GEOIP` | 完全一致 |
| `MATCH` | `FINAL` | Clash 的 MATCH 对应 Loon 的 FINAL |
| `RULE-SET` | 转为 `[Remote Rule]` | 需查找对应 rule-provider URL |

#### proxy-groups 中 `use` + `filter` 的处理

Clash 的 proxy-group 可以通过 `use` 引用 proxy-provider，并用 `filter` 正则筛选。Loon 的对应机制是：
1. `[Remote Proxy]` 定义订阅源
2. `[Remote Filter]` 用 `NameRegex` 对订阅源节点做正则筛选
3. `[Proxy Group]` 引用筛选器名称

这是转换中最复杂的部分。

## Key Technical Decisions

- **语言选择：Python 3**：YAML 解析成熟（PyYAML），字符串处理方便，无需编译
- **单文件脚本**：项目简单，一个 `converter.py` 即可，不需要复杂的包结构
- **rule-providers URL 转换策略**：blackmatrix7 的规则集同时提供 Clash 和 Loon 格式，URL 路径中 `rule/Clash/` 替换为 `rule/Loon/`，文件扩展名 `.yaml` 替换为 `.list`。对于 ACL4SSR 等其他源，保留原 URL 并添加注释提示用户检查兼容性
- **filter 到 Remote Filter 的映射**：为每个使用了 `use` + `filter` 的 proxy-group 自动生成一个 `[Remote Filter]` 条目，命名为 `{group_name}_Filter`
- **不支持的特性处理**：输出为注释行 `# [WARNING] ...`，不静默丢弃
- **dialer-proxy 到 Proxy Chain 的转换**：Clash 的 `dialer-proxy` 字段表示节点 A 的流量先经过节点/策略组 B。Loon 的 `[Proxy Chain]` 段可以直接表达这种关系：`A (Chain) = A, B, udp=true`。在策略组中引用这些节点时，替换为 Chain 名称

## Open Questions

### Resolved During Planning

- **Q: Loon 的 `[Remote Rule]` 能否直接使用 Clash 格式的规则集 URL？**
  A: 不能。Loon 的规则集格式是纯文本 `.list`，每行一条规则。blackmatrix7 同时提供两种格式，需要替换 URL 路径。

- **Q: Clash 的 `RULE-SET` 规则如何映射？**
  A: 每个 `RULE-SET,name,policy` 规则对应一个 `[Remote Rule]` 条目。从 `rule-providers` 中查找该 name 的 URL，转换后写入 `[Remote Rule]`。本地 `[Rule]` 中不再保留 RULE-SET 行。

- **Q: proxy-group 中同时有 `proxies` 和 `use` 怎么处理？**
  A: Loon 的策略组可以同时包含本地节点名和筛选器名。直接将 `proxies` 列表中的节点名和生成的 `Remote Filter` 名称一起放入策略组定义中。

### Deferred to Implementation

- ACL4SSR 等非 blackmatrix7 规则源的 URL 转换细节，需要实际测试 Loon 是否能解析
- Clash 订阅 URL 中的 token 参数是否需要调整（大多数订阅服务同时支持多种客户端格式）

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
读取 all-in-one.yaml
    |
    v
解析 YAML -> dict
    |
    +---> convert_general(config) -> [General] 文本
    +---> convert_proxies(config["proxies"]) -> [Proxy] 文本
    +---> convert_proxy_chains(config["proxies"]) -> [Proxy Chain] 文本
    +---> convert_proxy_providers(config["proxy-providers"]) -> [Remote Proxy] 文本
    +---> convert_remote_filters(config["proxy-groups"]) -> [Remote Filter] 文本
    +---> convert_proxy_groups(config["proxy-groups"]) -> [Proxy Group] 文本
    +---> convert_rules(config["rules"], config["rule-providers"]) -> [Rule] + [Remote Rule] 文本
    +---> convert_dns_and_hosts(config) -> [Host] 文本（DNS 部分合入 General）
    |
    v
拼接所有段落 -> 写入 output.conf
```

## Implementation Units

- [ ] **Unit 1: 项目骨架与 YAML 解析**

**Goal:** 创建 `converter.py`，实现 CLI 入口和 YAML 解析

**Requirements:** R1

**Dependencies:** None

**Files:**
- Create: `converter.py`
- Create: `requirements.txt`

**Approach:**
- 使用 `argparse` 接收输入文件路径和输出文件路径
- 使用 `PyYAML` 解析 YAML
- 定义主函数骨架，按顺序调用各转换函数
- 每个转换函数返回字符串，最终拼接写入文件

**Patterns to follow:**
- 标准 Python CLI 脚本结构

**Test scenarios:**
- Happy path: 传入 `all-in-one.yaml`，脚本不报错，输出非空文件
- Error path: 传入不存在的文件，输出友好错误信息
- Edge case: 传入空 YAML 文件，输出仅含段落标题的骨架配置

**Verification:**
- `python converter.py all-in-one.yaml -o output.conf` 能运行并生成文件

---

- [ ] **Unit 2: [General] 段转换**

**Goal:** 将 Clash 的通用配置和 DNS 配置转换为 Loon 的 `[General]` 段

**Requirements:** R7, R9

**Dependencies:** Unit 1

**Files:**
- Modify: `converter.py`

**Approach:**
- 从 `dns.nameserver` 提取 UDP DNS -> `dns-server`
- 从 `dns.fallback` 中提取 DoH URL -> `doh-server`
- `ipv6: false` -> `ip-mode = ipv4-only`
- `allow-lan: true` -> `allow-wifi-access = true`
- 生成合理的默认值：`skip-proxy`、`bypass-tun`、`proxy-test-url`、`test-timeout`
- `dns.fake-ip-filter` 中的域名 -> `real-ip`
- `dns.listen` 中的端口 -> `hijack-dns = *:53`

**Test scenarios:**
- Happy path: DNS 配置完整时，生成包含 dns-server 和 doh-server 的 General 段
- Edge case: 无 fallback DNS 时，doh-server 行不生成
- Edge case: ipv6 为 true 时，ip-mode 设为 dual

**Verification:**
- 输出的 `[General]` 段包含有效的 dns-server、ip-mode、proxy-test-url 等字段

---

- [ ] **Unit 3: [Proxy] 段转换——节点格式映射**

**Goal:** 将 Clash 的 `proxies` 列表转换为 Loon 的 `[Proxy]` 段

**Requirements:** R2

**Dependencies:** Unit 1

**Files:**
- Modify: `converter.py`

**Approach:**
- 遍历 `proxies` 列表，根据 `type` 字段分发到不同的转换函数
- **trojan**: `名称 = trojan,server,port,"password",skip-cert-verify=false,udp=true`
- **ss**: `名称 = Shadowsocks,server,port,cipher,"password",fast-open=false,udp=true`
- **vmess**: `名称 = vmess,server,port,cipher,"uuid",transport=tcp/ws,alterId=0,...`
- 使用了 `dialer-proxy` 的节点照常输出到 `[Proxy]`（节点本身的定义不变），代理链关系在 Unit 3b 中处理
- 密码用双引号包裹

**Test scenarios:**
- Happy path: trojan 节点正确转换，包含 server、port、password
- Happy path: ss 节点正确转换，包含 cipher
- Edge case: 节点名称包含特殊字符（emoji）时保持原样
- Edge case: 有 dialer-proxy 的 ss 节点，节点本身正常输出（代理链在 Unit 3b 处理）
- Error path: 遇到不支持的协议类型（如 snell），输出注释警告并跳过

**Verification:**
- 输出的每个节点行符合 Loon 节点格式规范

---

- [ ] **Unit 3b: [Proxy Chain] 段转换**

**Goal:** 将 Clash 中使用 `dialer-proxy` 的节点关系转换为 Loon 的 `[Proxy Chain]` 段

**Requirements:** R10

**Dependencies:** Unit 3

**Files:**
- Modify: `converter.py`

**Approach:**
- 遍历 `proxies`，收集所有设置了 `dialer-proxy` 的节点
- 对于每个这样的节点（如节点 `A`，`dialer-proxy` 值为 `B`）：
  - 生成 Proxy Chain 行：`A (Chain) = A, B, udp=true`
  - 其中 `A` 是 SS 节点本身，`B` 是 dialer-proxy 指向的策略组或节点
- 在 Clash 配置中，`Proxy Chain` 策略组引用了这些 SS 节点名。转换时需要将 `[Proxy Group]` 中对这些节点的引用替换为对应的 Proxy Chain 名称
- 返回一个映射表 `{原节点名: Chain名}` 供 Unit 5 使用

**Test scenarios:**
- Happy path: `🇺🇸 sanjose-oracle (SS)` 有 `dialer-proxy: Dialer`，生成 `🇺🇸 sanjose-oracle (SS) (Chain) = 🇺🇸 sanjose-oracle (SS), Dialer, udp=true`
- Happy path: 多个节点使用同一个 dialer-proxy，各自生成独立的 Proxy Chain 行
- Edge case: 没有任何节点使用 dialer-proxy 时，`[Proxy Chain]` 段为空或不输出

**Verification:**
- 每个使用了 dialer-proxy 的节点都有对应的 Proxy Chain 条目
- Proxy Chain 格式符合 Loon 规范：`名称 = 入口节点, 出口节点/策略组, udp=true`

---

- [ ] **Unit 4: [Remote Proxy] 和 [Remote Filter] 段转换**

**Goal:** 将 Clash 的 `proxy-providers` 转换为 Loon 的 `[Remote Proxy]`，并为使用了 `filter` 的 proxy-group 生成 `[Remote Filter]`

**Requirements:** R3, R4

**Dependencies:** Unit 1

**Files:**
- Modify: `converter.py`

**Approach:**
- `proxy-providers` 中每个 provider -> `[Remote Proxy]` 的一行：`别名 = URL`
  - `exclude-filter` 暂无法直接映射到 Remote Proxy，添加注释提示
- 遍历 `proxy-groups`，对于使用了 `use` + `filter` 的组：
  - 为每个组生成一个 `[Remote Filter]` 条目
  - 格式：`{组名}_Filter = NameRegex, {provider别名1}, {provider别名2}, FilterKey = "{filter正则}"`
  - 如果组没有 filter 但有 use，生成一个不带 FilterKey 的筛选器（选择所有节点），或者使用排除信息节点的通用正则

**Test scenarios:**
- Happy path: 两个 proxy-provider 正确生成两行 Remote Proxy
- Happy path: 带 filter 的 proxy-group 生成对应的 Remote Filter
- Edge case: proxy-group 有 use 但无 filter（如 All Nodes），生成带排除过滤的 Remote Filter
- Edge case: 多个 proxy-group 引用相同的 provider 但不同 filter，生成不同的 Remote Filter

**Verification:**
- Remote Proxy 段包含所有订阅源 URL
- Remote Filter 段为每个需要筛选的策略组生成了正确的正则筛选器

---

- [ ] **Unit 5: [Proxy Group] 段转换**

**Goal:** 将 Clash 的 `proxy-groups` 转换为 Loon 的 `[Proxy Group]` 段

**Requirements:** R4

**Dependencies:** Unit 3b, Unit 4（需要知道 Remote Filter 的命名和 Proxy Chain 映射）

**Files:**
- Modify: `converter.py`

**Approach:**
- **select 类型**: `名称 = select, 节点1, 节点2, ...`
  - `proxies` 列表中的名称直接作为成员
  - 如果有 `use`，将对应的 Remote Filter 名称加入成员列表
- **url-test 类型**: `名称 = url-test, 成员..., url=URL, interval=秒, tolerance=毫秒`
  - Clash 的 interval 单位是秒，Loon 也是秒，直接映射
  - Clash 的 tolerance 单位是毫秒，Loon 也是毫秒，直接映射
- **fallback 类型**: `名称 = fallback, 成员..., url=URL, interval=秒, max-timeout=毫秒`
- **load-balance 类型**: `名称 = load-balance, 成员..., url=URL, interval=秒, algorithm=pcc`
- 对于成员列表中引用了有 dialer-proxy 的节点，替换为对应的 Proxy Chain 名称（使用 Unit 3b 返回的映射表）
- 对于 Clash 的 `Proxy Chain` select 组（专门引用 dialer-proxy 节点的组），其成员全部替换为 Proxy Chain 名称

**Test scenarios:**
- Happy path: select 组包含正确的节点列表
- Happy path: url-test 组包含 url、interval、tolerance 参数
- Happy path: 引用 provider 的组，成员列表中包含 Remote Filter 名称
- Happy path: `Proxy Chain` 策略组中的 SS 节点名被替换为对应的 Proxy Chain 名称
- Edge case: 组同时有 proxies 和 use，两者都出现在成员列表中

**Verification:**
- 每个策略组行格式正确，参数完整

---

- [ ] **Unit 6: [Rule] 和 [Remote Rule] 段转换**

**Goal:** 将 Clash 的 `rules` 和 `rule-providers` 转换为 Loon 的 `[Rule]` 和 `[Remote Rule]` 段

**Requirements:** R5, R6

**Dependencies:** Unit 1

**Files:**
- Modify: `converter.py`

**Approach:**
- 遍历 `rules` 列表：
  - `RULE-SET,name,policy` -> 从 `rule-providers` 查找 URL，转换后写入 `[Remote Rule]`
    - blackmatrix7 URL: `rule/Clash/` -> `rule/Loon/`，`.yaml` -> `.list`
    - ACL4SSR URL: 尝试类似替换，添加注释提示检查
  - `MATCH,policy` -> `FINAL,policy`
  - `GEOIP,CN,DIRECT` -> `GEOIP,CN,DIRECT`（格式一致）
  - `DOMAIN-SUFFIX,xxx,POLICY` -> `DOMAIN-SUFFIX,xxx,POLICY`（格式一致）
  - `IP-CIDR,xxx,POLICY` -> `IP-CIDR,xxx,POLICY`（格式一致）
  - 注释行和空行保留
- Remote Rule 格式：`URL, policy=POLICY, enabled=true`

**Test scenarios:**
- Happy path: DOMAIN-SUFFIX 规则原样保留
- Happy path: RULE-SET 规则正确转换为 Remote Rule 条目
- Happy path: MATCH 规则转换为 FINAL
- Happy path: blackmatrix7 URL 正确替换路径和扩展名
- Edge case: 规则值中有空格（如 `DOMAIN-SUFFIX,bilibili.com, DIRECT`），正确 trim
- Edge case: ACL4SSR URL 添加兼容性注释
- Edge case: 注释行（以 # 开头）保留

**Verification:**
- [Rule] 段不包含 RULE-SET 行
- [Remote Rule] 段包含所有规则集的 URL
- MATCH 已被替换为 FINAL

---

- [ ] **Unit 7: [Host] 段转换**

**Goal:** 将 Clash 的 `hosts` 配置转换为 Loon 的 `[Host]` 段

**Requirements:** R8

**Dependencies:** Unit 1

**Files:**
- Modify: `converter.py`

**Approach:**
- Clash hosts 格式：`域名: IP或域名`
- Loon Host 格式：`域名 = IP或域名`
- 直接映射，将 `:` 替换为 ` = `

**Test scenarios:**
- Happy path: `*.clash.dev: 127.0.0.1` -> `*.clash.dev = 127.0.0.1`
- Happy path: `www.googe.com.hk: www.google.com` -> `www.googe.com.hk = www.google.com`

**Verification:**
- [Host] 段包含所有 hosts 映射

---

- [ ] **Unit 8: 集成测试与输出验证**

**Goal:** 用实际的 `all-in-one.yaml` 运行转换，验证输出的完整性和正确性

**Requirements:** R11

**Dependencies:** Unit 2-7（含 Unit 3b）

**Files:**
- Modify: `converter.py`（修复集成问题）

**Approach:**
- 运行 `python converter.py all-in-one.yaml -o loon.conf`
- 人工检查输出文件的每个段落
- 确认所有节点、策略组、规则、DNS 配置都已正确转换
- 确认 `[Proxy Chain]` 段包含所有 dialer-proxy 节点的代理链定义
- 确认 `Proxy Chain` 策略组中的节点引用已替换为 Chain 名称

**Test scenarios:**
- Integration: 完整转换 all-in-one.yaml，输出文件包含所有预期段落
- Integration: 输出文件中无 Python 异常或空段落
- Integration: trojan 节点数量与源文件一致
- Integration: ss 节点数量与源文件一致
- Integration: 策略组数量与源文件一致
- Integration: Proxy Chain 数量与使用 dialer-proxy 的节点数量一致（源文件中有 6 个）
- Integration: Remote Rule 数量与 rule-providers 数量一致

**Verification:**
- 输出的 `loon.conf` 结构完整，可被 Loon 导入

## System-Wide Impact

- **Interaction graph:** 纯离线脚本，不影响任何运行中的系统
- **Error propagation:** 解析错误应输出清晰的错误信息并退出，不生成半成品文件
- **State lifecycle risks:** 无状态，每次运行都是全量转换

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| blackmatrix7 的 Loon 规则集 URL 路径规则可能变化 | 转换时添加注释提示用户验证 URL 可访问性 |
| 部分 Clash 订阅 URL 返回的格式 Loon 可能无法直接解析 | 在 [General] 中配置 resource-parser（SubStore 解析器） |
| dialer-proxy 链式关系可能嵌套多层 | 当前仅处理单层 dialer-proxy，多层嵌套输出 WARNING 注释 |
| Clash 的 exclude-filter 在 Loon Remote Proxy 中无直接对应 | 在 Remote Filter 中用排除正则实现类似效果 |

## Sources & References

- Loon 官方手册: https://nsloon.app/docs/intro
- Loon 示例配置: https://github.com/Loon0x00/LoonExampleConfig
- Clash (mihomo) 配置文档: https://wiki.metacubex.one/en/config/
- blackmatrix7 规则集: https://github.com/blackmatrix7/ios_rule_script
- 源配置文件: `all-in-one.yaml`
