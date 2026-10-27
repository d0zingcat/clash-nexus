# Egern current-documentation audit

Checked: 2026-10-27. Baseline: main after PR #21.

The official pages describe current capabilities but do not give introduction
dates for individual fields. The findings below are compatibility gaps against
the current documentation, not a claim that every feature was newly released.

## Official sources

- [Egern proxies and transports](https://egernapp.com/docs/configuration/proxies/)
- [Egern policy groups](https://egernapp.com/docs/configuration/policy_groups/)
- [Egern DNS](https://egernapp.com/docs/configuration/dns/)
- [Egern rules](https://egernapp.com/docs/configuration/rules/)
- [Egern full example](https://egernapp.com/docs/configuration/example/)
- Mihomo source semantics: [AnyTLS](https://wiki.metacubex.one/en/config/proxies/anytls/),
  [TUIC](https://wiki.metacubex.one/en/config/proxies/tuic/),
  [WireGuard](https://wiki.metacubex.one/en/config/proxies/wg/),
  [Snell](https://wiki.metacubex.one/en/config/proxies/snell/),
  [SSH](https://wiki.metacubex.one/en/config/proxies/ssh/),
  [TLS](https://wiki.metacubex.one/en/config/proxies/tls/).

## Implemented adaptations

| Area | Previous behavior | Current conversion |
| --- | --- | --- |
| AnyTLS | Node skipped | Password, SNI, UDP, TFO and certificate verification; explicitly emit `skip_tls_verify: false` for the Clash default because Egern's AnyTLS default differs |
| TUIC | Node skipped | v5 UUID/password, ALPN, UDP relay mode, TLS options; reject v4 token and unrepresentable SNI/IP overrides |
| WireGuard | Node skipped | Single-peer shorthand, local addresses, keys, reserved bytes (list or Base64), MTU, keepalive, remote DNS |
| Snell | Node skipped | v1–v4, PSK, version, reuse and http/tls obfuscation |
| SSH | Node skipped | Password or inline private key, host-key pins, port and username |
| SOCKS5 TLS | TLS silently lost | Emit `socks5_tls` with SNI and certificate settings |
| VMess/VLESS gRPC | Transport silently lost | Emit `transport.grpc`, service name, SNI and TLS/REALITY; reject plaintext gRPC because Egern always encrypts it |
| VMess REALITY | Options lost | Preserve REALITY on TCP and gRPC |
| TLS certificate pin | Lost | Map Clash `fingerprint` to `fingerprint_sha256`; do not confuse this with `client-fingerprint` browser impersonation |
| Proxy common fields | IP strategy/TFO inconsistent | Map documented IP-version values and TFO; preserve HTTP(S) custom headers |
| Mixed policy group | Extra nested provider groups | Use native `policies` plus `urls`, retaining one selection pool |
| Policy group options | Lost | Preserve latency test URL, icon, hidden, and round-robin/hash load-balancing strategy |
| Logical rules | Dropped as unsupported | Nested AND/OR/NOT with Egern's list/object match shapes; reject the entire rule on an unsupported or malformed operand |
| IP rules | Some no-resolve flags lost | Preserve for CIDR, IPv6 CIDR and ASN as well as GEOIP |
| NETWORK / SRC-PORT | Uppercase protocol / incorrect destination-port approximation | Lowercase protocol; warn and skip source-port matching |
| DNS policies | Unordered, first server only, system replaced with bootstrap | Preserve source order and `system`; create named upstreams containing every server in a policy list |
| DoH3 | Classified as plain DNS | Dedicated DoH3 upstream group |
| Unsupported DNS policies | Silent drops or incompatible URLs | Warn on geosite and incompatible/unresolved DNS rule providers |
| Missing proxy providers | External group with empty URLs | Warn and use a native group with `DIRECT` fallback |

## Boundaries and manual configuration

- Existing provider-only `external` groups remain valid: the official docs retain
  this legacy form. Only mixed groups need the native `policies` + `urls` form.
- Remote subscription URLs must still return a format Egern understands. Use
  `expand_proxy_providers=1` for Clash-only providers; changing the group shape
  does not convert their remote payloads.
- Egern's `smart`, `conditional`, `flatten`, `block_quic` and regex priorities
  are native capabilities. No equivalent Clash source behavior is inferred or
  injected automatically.
- Egern's Snell v5 is documented as a v4 alias. Real Snell v5 and Snell
  ShadowTLS/ResTLS/JLS are not converted into v4 or plain Snell.
- Multi-peer WireGuard, restricted allowed-IPs and AmneziaWG require manual
  handling; nodes are skipped with a warning rather than losing these options.
- SSH key paths/encrypted keys/passphrases need manual handling. SSH host-key
  algorithm restrictions and advanced connection settings have no conversion.
- Clash `proxy-server-nameserver` is documented as resolving proxy endpoints.
  Egern describes `proxy_nameservers` as forcing proxy DNS queries through a
  separate direct path. These are not assumed equivalent: emit a warning and
  leave the Egern-specific choice to the user.
- DNS fallback-filter semantics, geosite data, Clash DNS URL fragments,
  Hysteria2 bandwidth/port hopping, advanced AnyTLS session tuning, browser TLS
  impersonation, ECH and new wrapping transports are not fully mapped.
- Egern's YAML rule sets and Surge rule sets are supported by Egern itself, but
  arbitrary Clash provider URLs are not automatically rewritten. Existing
  blackmatrix7 Clash-to-Surge conversion remains conservative.
- Egern-specific modules, rewriting, scripting and widgets have no equivalent
  Clash input sections and are outside this converter's scope.

## Validation

Regression coverage includes output YAML decoding, node/group references,
TLS verification defaults and certificate pins, supported protocols, rejected
variants, TLS/REALITY gRPC, native mixed groups, DNS order and multi-server
upstreams, logical nesting and whole-rule rejection, and no-resolve flags.

Run `go test ./...` and `go vet ./...`. Egern application import and actual
proxy connectivity require device testing; Go YAML parsing alone is not an
Egern schema or connectivity validator.
