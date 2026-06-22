# Loon 输入配置转换设计

## 目标

支持把 Loon 配置作为输入，转换为 Clash/Mihomo YAML、Egern YAML 或 Quantumult X 配置。现有 Clash YAML 输入及其所有输出行为保持不变。

## 范围

- 新增 Loon 输入来源；输入来源默认仍为 Clash YAML。
- 新增 `clash` 输出目标，输出标准 Mihomo YAML。
- Loon 输入可输出至 `clash`、`egern`、`qx`。
- Web、CLI、JSON API、文件上传和远程订阅接口均可显式指定输入来源。

不在本次范围内：将 Loon 的 Rewrite、Script、Plugin、MITM 内容转换为其他应用的等价功能。

## 架构

新增 Loon 解析器，将 INI 风格的 Loon 配置转换为项目现有的 Clash/Mihomo 中间模型（`map[string]interface{}` 与 YAML 节点）。随后按输出目标分发：

- `clash`：将中间模型序列化为 Mihomo YAML；
- `egern`：复用现有 Egern 转换器；
- `qx`：复用现有 Quantumult X 转换器及 `qx_final_proxy_chain` 选项。

这样节点、策略组、规则与规则集的目标转换逻辑只保留一份，避免维护两套 Loon 到各目标的实现。

## Loon 映射

| Loon 段 | 中间模型 |
| --- | --- |
| `[Proxy]` | `proxies` |
| `[Proxy Group]` | `proxy-groups` |
| `[Rule]` | `rules` |
| `[Remote Rule]` | `rule-providers` 与对应 `RULE-SET` |
| `[General]` 中可等价设置 | Mihomo 顶层网络与 DNS 配置 |

解析器会保留可用的节点和策略组引用。没有可靠等价表示的字段不会伪造输出。

## 错误和警告

- 非法 Loon 语法或缺少必须字段会返回带位置/段落上下文的输入错误。
- `[Rewrite]`、`[Script]`、`[Plugin]`、`[MITM]` 以及无法映射的 `[General]` 字段会产生 warning，并从输出中省略。
- `source=loon` 与 `target=loon` 是无意义组合，API/CLI/UI 应拒绝或不提供该选项。
- Clash 输入继续支持既有全部目标；新增 `clash` 目标时应避免提供 Clash 到 Clash 的无变化转换入口。

## 接口与界面

- CLI 增加 `-source`，取值为 `clash`（默认）或 `loon`。
- API 请求、multipart 表单和订阅 URL 增加 `source`。
- Web 增加输入格式选择器。选中 Loon 时，文本区域、文件上传和 URL 标签改为 Loon 配置表述；目标按钮只显示 Clash、Egern、QX。
- 选中 Clash 时保留现有目标行为，并提供新增 Clash/Mihomo YAML 目标时避免同源同目标转换。

## 测试

- Loon 示例的 Proxy、Proxy Group、Rule、Remote Rule 分别转换到 Clash、Egern、QX。
- 非支持段产生可见 warning，而不导致整个转换失败。
- 非法 Loon 输入产生结构化错误。
- 各入口（服务、HTTP API、CLI）正确传递 `source`。
- 现有 Clash 输入回归测试保持通过。
