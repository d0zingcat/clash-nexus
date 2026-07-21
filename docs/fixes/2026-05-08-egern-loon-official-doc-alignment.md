# Egern and Loon Official Documentation Alignment Fixes

Date: 2026-05-08

## Background

This change set reviewed the Egern and Loon converters against the current official documentation and fixed conversion behavior that could produce invalid, lossy, or semantically different target configs.

The main focus was preserving routing, DNS, provider refresh, and transport semantics when converting Clash/Mihomo YAML to Egern YAML or Loon conf.

## Egern Fixes

- Converted DNS `nameserver-policy` targets now preserve dedicated DNS server addresses instead of collapsing them into broad upstream names such as `doh` or `default`.
- DNS `nameserver-policy` entries using `rule-set:` now convert to Egern `proxy_rule_set`.
- Blackmatrix7 Clash rule-provider URLs used by DNS rule sets are converted to Surge `.list` URLs when possible, matching Egern's supported remote rule set format.
- Vmess/Vless WebSocket and WSS transports now preserve `headers.Host` separately from TLS SNI.
- `proxy-providers.interval` now maps to Egern external policy group's `update_interval`.
- Added Egern tests covering dedicated DNS policy targets, DNS rule-set forwarding, WSS Host/SNI preservation, and external update interval mapping.

## Loon Fixes

- DNS `h3://` servers now emit `doh3-server`.
- Clash `fake-ip-filter` patterns using `+.` now convert to Loon-compatible `*.` entries in `real-ip`.
- Loon logic rules `AND`, `OR`, and `NOT` are preserved instead of being marked unsupported.
- Clash `NETWORK` rules now map to Loon `PROTOCOL` rules.
- Trojan HTTP transport now maps `network: http` and `http-opts`.
- VLESS HTTP transport now maps `network: http` and `http-opts`.
- Added WireGuard proxy conversion.
- Added AnyTLS proxy conversion using the documented Loon node style and common Clash fields.
- Added Loon tests for DNS, logic rules, `NETWORK` mapping, Trojan/VLESS HTTP transport, WireGuard, and AnyTLS.
- Updated README protocol and DNS support notes for Loon.

## Verification

The following checks passed:

```bash
go test ./converter/egern
go test ./converter/loon
go test ./...
go run . -target egern input/example.yaml
go run . -target loon input/example.yaml
```

## Notes

- Loon SNI output remains `sni=...` because the current official Loon node documentation uses that key.
- AnyTLS support is conservative: it maps core fields (`server`, `port`, `password`, `sni`, TLS verification, fingerprint, ALPN) and can be extended if Loon documents more Clash-compatible options.
- Egern still intentionally limits non-Blackmatrix7 Clash remote rule-provider conversion where compatibility cannot be inferred safely.
