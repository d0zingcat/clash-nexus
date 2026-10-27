# Loon current-documentation alignment

Checked: 2026-10-27. Based on main after PR #21; independent of the Egern PR.

## Sources and version requirements

- [Single-node configuration](https://nsloon.app/en/docs/Node/): node DNS,
  TLS, Hysteria2, AnyTLS, WireGuard and supported transports.
- [Subscription configuration](https://nsloon.app/en/docs/Node/subscription/):
  subscription DNS and section-based subscription payloads.
- [General](https://nsloon.app/en/docs/General/): include-tun and DNS.
- [Domain rules](https://nsloon.app/en/docs/Rule/domain_rule/): wildcard rules.
- [Policy groups](https://nsloon.app/en/docs/Policy/policygroup/): algorithms and
  timeout units.
- [Mihomo Hysteria2](https://wiki.metacubex.one/en/config/proxies/hysteria2/),
  [AnyTLS](https://wiki.metacubex.one/en/config/proxies/anytls/), and
  [WireGuard](https://wiki.metacubex.one/en/config/proxies/wg/) establish the
  source field meanings.

The documentation explicitly dates `server-dns` to Loon 3.5.2 (996)+,
`include-tun` to Build 1007+, and `DOMAIN-WILDCARD` to Build 1008+. Other
changes below close current compatibility gaps; their release dates are not
inferred. Generated configurations target these current capabilities and do not
select syntax based on an older client version.

## Adaptations

| Input or feature | Output and behavior |
| --- | --- |
| proxy-server-nameserver | Quoted server-dns on local nodes and Remote Proxy entries; normal global DNS stays in General |
| Unsupported node DNS / proxy-server-nameserver-policy | Warn and omit the whole node DNS override rather than applying only a subset of its resolver paths |
| DOMAIN-WILDCARD | Preserve the rule rather than marking it unsupported |
| tun.route-address | When tun is enabled, normalize/deduplicate IPv4 CIDRs into additive include-tun; warn about unsupported IPv6 and bare IP entries |
| SOCKS5 with TLS | Emit the previously missing over-tls=true switch |
| Common node fields | Map ip-version to node ip-mode, certificate fingerprint to tls-cert-sha256, and tfo to fast-open; preserve the explicitly selected chrome147 profile |
| VMess/Trojan REALITY | Preserve public key and short ID; VMess/VLESS enable over-tls when REALITY is configured |
| Hysteria2 | Salamander password, quoted port ranges (hyphen to colon), fixed hop interval, ALPN and download-bandwidth with Mbps conversion |
| AnyTLS | idle-session-timeout in seconds; retain the required positional password fixed previously |
| WireGuard | Multiple peers, IPv6 endpoint brackets, Base64 reserved bytes, IPv4/IPv6 tunnel DNS, persistent-keepalive including zero, documented keepalive spelling |
| Subscription content | Accept native nodes, URIs and General/Host/Proxy sections, raw or Base64; continue warning about full client configurations |
| load-balance | Use documented PCC capitalization and preserve max-timeout in milliseconds |
| Resource parser | Use the latest official-documented Sub-Store release download URL |

## Semantics and limits

- Loon's `include-tun` adds routes to its existing routing table. It does not
  reproduce Clash's complete route-address selection semantics. The generated
  configuration includes a note about this difference.
- `server-dns` takes precedence over SSID/global DNS and does not fall back on
  failure. The converter only maps compatible plain IP/system, DoH, DoQ and
  DoH3 lists. DoT and Clash DNS URL fragments are not silently rewritten.
- Unexpanded providers get `server-dns` at the subscription level; expanded
  providers get it on each emitted local node. Remote payload conversion still
  depends on the resource parser or provider expansion.
- Loon documents TCP, WS and HTTP for VMess/VLESS. gRPC, h2 and other unsupported
  source transports are skipped with warnings, and group references are pruned.
- Loon handles Trojan transport=http as WebSocket. Clash HTTP transport is not
  equivalent, so such nodes are skipped rather than silently reinterpreted.
- Hysteria2 Gecko, Realm and randomized hop intervals are skipped. Upload-side
  bandwidth and additional QUIC tuning have no automatic mapping. Only
  download-bandwidth is mapped; accepted numeric units are bps/kbps/Mbps/Gbps.
- AnyTLS idle-session checking/minimum idle session settings are not inferred
  as Loon max-stream-count, because they describe different behaviors.
- WireGuard selects the first tunnel DNS address in each IP family, matching
  Loon's separate dns/dnsv6 fields. AmneziaWG requires manual configuration.
- Loon-specific scripts, plugins, IP rewriting, custom JavaScript protocols and
  UI settings have no equivalent Clash inputs and are not synthesized.
- This change does not add undocumented TUIC, Snell or SSH conversion.
- Policy fallback/load-balance max-timeout is milliseconds, unlike Egern's
  seconds. Existing fallback conversion was already correct and remains so.

## Validation

- Regression tests exercise local/subscription server DNS with a local HTTP
  fixture, invalid DNS lists, SOCKS5 TLS, TLS profile and IP-mode preservation,
  Hysteria2 options and bandwidth units, AnyTLS timeout, rejected transports,
  group pruning, multiple WireGuard peers and IPv6 endpoints, route
  normalization and wildcard rules, and native/Base64 subscription formats.
- Run `go test ./...`, `go vet ./...`, and `git diff --check`.
- CLI conversion of the example configuration validates the assembly path.
- Device import and network connectivity have not been tested. Text assertions
  are not a replacement for the Loon application's parser or real endpoints.
