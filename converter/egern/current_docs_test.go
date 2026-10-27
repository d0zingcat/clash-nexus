package egern

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func convertDocument(t *testing.T, input string) (map[string]interface{}, []string) {
	t.Helper()
	var config map[string]interface{}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(input), &config); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(input), &root); err != nil {
		t.Fatal(err)
	}
	content, warnings, err := New().Convert(config, &root)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := yaml.Unmarshal(content, &got); err != nil {
		t.Fatal(err)
	}
	return got, warnings
}

func TestCurrentDocumentedProxyProtocols(t *testing.T) {
	got, warnings := convertDocument(t, `
proxies:
  - {name: AnyTLS, type: anytls, server: example.com, port: 443, password: test, udp: true, tfo: true, ip-version: ipv4-prefer}
  - {name: TUIC, type: tuic, server: example.com, port: 443, uuid: test-uuid, password: test, alpn: [h3], udp-relay-mode: quic}
  - {name: Snell, type: snell, server: example.com, port: 443, psk: test, version: 4, udp: true, reuse: true, obfs-opts: {mode: tls, host: example.org}}
  - {name: WG, type: wireguard, server: example.com, port: 443, private-key: private, public-key: public, ip: 172.16.0.2, ipv6: "fd00::2", reserved: AQID, persistent-keepalive: 25, remote-dns-resolve: true, dns: [1.1.1.1]}
  - {name: TLS-SOCKS, type: socks5, server: example.com, port: 443, tls: true, sni: example.org, fingerprint: "aa:bb", skip-cert-verify: true}
  - {name: SSH, type: ssh, server: example.com, username: root, password: test, host-key: ["ssh-ed25519 AAAA"]}
proxy-groups:
  - {name: Select, type: select, proxies: [AnyTLS, TUIC, Snell, WG, TLS-SOCKS, SSH]}
`)
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	proxies := got["proxies"].([]interface{})
	if len(proxies) != 6 {
		t.Fatalf("got %d proxies", len(proxies))
	}
	checks := []struct {
		kind   string
		fields map[string]interface{}
	}{
		{"anytls", map[string]interface{}{"skip_tls_verify": false, "udp_relay": true, "tfo": true, "ip_version": "v4_prefer"}},
		{"tuic", map[string]interface{}{"uuid": "test-uuid", "password": "test", "udp_relay_mode": "quic", "alpn": []interface{}{"h3"}}},
		{"snell", map[string]interface{}{"version": 4, "psk": "test", "udp_relay": true, "reuse": true, "obfs": "tls", "obfs_host": "example.org"}},
		{"wireguard", map[string]interface{}{"private_key": "private", "peer_public_key": "public", "local_ipv4": "172.16.0.2", "local_ipv6": "fd00::2", "reserved": []interface{}{1, 2, 3}, "keepalive": 25, "dns_servers": []interface{}{"1.1.1.1"}}},
		{"socks5_tls", map[string]interface{}{"sni": "example.org", "fingerprint_sha256": "aa:bb"}},
		{"ssh", map[string]interface{}{"port": 22, "host_keys": []interface{}{"ssh-ed25519 AAAA"}}},
	}
	for i, check := range checks {
		cfg := proxies[i].(map[string]interface{})[check.kind].(map[string]interface{})
		for field, want := range check.fields {
			if !reflect.DeepEqual(cfg[field], want) {
				t.Errorf("%s.%s = %#v, want %#v", check.kind, field, cfg[field], want)
			}
		}
		if check.kind == "socks5_tls" && cfg["skip_tls_verify"] != nil {
			t.Error("certificate pin should replace skip_tls_verify")
		}
	}
	group := got["policy_groups"].([]interface{})[0].(map[string]interface{})["select"].(map[string]interface{})
	if len(group["policies"].([]interface{})) != 6 {
		t.Fatalf("converted nodes were pruned from group: %v", group)
	}
}

func TestCurrentGRPCTransports(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless"} {
		for _, security := range []string{"tls: true", "reality-opts: {public-key: public, short-id: abcd}"} {
			t.Run(protocol+"/"+security, func(t *testing.T) {
				got, warnings := convertDocument(t, `proxies:
  - {name: grpc, type: `+protocol+`, server: example.com, port: 443, uuid: test, network: grpc, sni: example.org, grpc-opts: {grpc-service-name: GunService}, `+security+`}
`)
				if len(warnings) != 0 {
					t.Fatal(warnings)
				}
				proxy := got["proxies"].([]interface{})[0].(map[string]interface{})[protocol].(map[string]interface{})
				grpc := proxy["transport"].(map[string]interface{})["grpc"].(map[string]interface{})
				if grpc["service_name"] != "GunService" || grpc["sni"] != "example.org" {
					t.Fatalf("gRPC = %#v", grpc)
				}
				if strings.HasPrefix(security, "reality") && grpc["reality"].(map[string]interface{})["public_key"] != "public" {
					t.Fatalf("Reality = %#v", grpc)
				}
			})
		}
	}
}

func TestUnsupportedProxyVariantsAreNotDowngraded(t *testing.T) {
	got, warnings := convertDocument(t, `proxies:
  - {name: TUIC4, type: tuic, token: test}
  - {name: Snell5, type: snell, version: 5}
  - {name: WG-peers, type: wireguard, peers: [{public-key: test}]}
  - {name: WG-reserved, type: wireguard, ip: 172.16.0.2, reserved: invalid}
  - {name: SSH-key, type: ssh, private-key: /tmp/key}
  - {name: plaintext-grpc, type: vless, network: grpc}
`)
	if len(warnings) != 6 || got["proxies"] != nil {
		t.Fatalf("warnings = %v, proxies = %#v", warnings, got["proxies"])
	}
}

func TestMixedGroupsUseNativeURLsAndPreserveSelection(t *testing.T) {
	got, warnings := convertDocument(t, `
proxy-providers:
  sub: {url: "https://example.com/sub", interval: 7200}
proxy-groups:
  - {name: Balance, type: load-balance, proxies: [DIRECT], use: [sub], strategy: round-robin, url: "https://example.com/check", hidden: true, icon: globe}
`)
	if len(warnings) != 0 {
		t.Fatal(warnings)
	}
	groups := got["policy_groups"].([]interface{})
	if len(groups) != 1 {
		t.Fatalf("got %d groups; helper groups should not be emitted", len(groups))
	}
	group := groups[0].(map[string]interface{})["load_balance"].(map[string]interface{})
	if group["algorithm"] != "round_robin" || group["latency_test_url"] != "https://example.com/check" || group["update_interval"] != 7200 || group["hidden"] != true || group["icon"] != "globe" {
		t.Fatalf("group = %#v", group)
	}
	if !reflect.DeepEqual(group["policies"], []interface{}{"DIRECT"}) || !reflect.DeepEqual(group["urls"], []interface{}{"https://example.com/sub"}) {
		t.Fatalf("mixed members = %#v", group)
	}
}

func TestDNSPreservesSystemMultipleServersAndOrder(t *testing.T) {
	got, warnings := convertDocument(t, `dns:
  default-nameserver: [223.5.5.5]
  nameserver: ["h3://dns.example.com/dns-query"]
  nameserver-policy:
    z.example.com: system
    a.example.com: ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
`)
	if len(warnings) != 0 {
		t.Fatal(warnings)
	}
	dns := got["dns"].(map[string]interface{})
	forward := dns["forward"].([]interface{})
	first := forward[0].(map[string]interface{})["domain"].(map[string]interface{})
	if first["match"] != "z.example.com" || first["value"] != "system" {
		t.Fatalf("first DNS rule = %#v", first)
	}
	second := forward[1].(map[string]interface{})["domain"].(map[string]interface{})
	upstreams := dns["upstreams"].(map[string]interface{})
	if !reflect.DeepEqual(upstreams[second["value"].(string)], []interface{}{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}) {
		t.Fatalf("dedicated upstream = %#v", upstreams)
	}
	if upstreams["doh3"] == nil {
		t.Fatalf("DNS = %#v", dns)
	}
}

func TestLogicalRulesPreserveNestedConditionsAndNoResolve(t *testing.T) {
	got, warnings := convertDocument(t, `rules:
  - AND,((NETWORK,UDP),(OR,((DST-PORT,443),(IP-CIDR,192.168.0.0/16,no-resolve)))),REJECT
  - NOT,((GEOIP,CN)),Proxy
  - IP-ASN,13335,DIRECT,no-resolve
  - IP-CIDR6,::1/128,DIRECT,no-resolve
`)
	if len(warnings) != 0 {
		t.Fatal(warnings)
	}
	rules := got["rules"].([]interface{})
	and := rules[0].(map[string]interface{})["and"].(map[string]interface{})
	children := and["match"].([]interface{})
	protocol := children[0].(map[string]interface{})["protocol"].(map[string]interface{})
	if and["policy"] != "REJECT" || protocol["match"] != "udp" || protocol["policy"] != nil {
		t.Fatalf("AND = %#v", and)
	}
	or := children[1].(map[string]interface{})["or"].(map[string]interface{})
	cidr := or["match"].([]interface{})[1].(map[string]interface{})["ip_cidr"].(map[string]interface{})
	if cidr["no_resolve"] != true {
		t.Fatalf("nested CIDR = %#v", cidr)
	}
	not := rules[1].(map[string]interface{})["not"].(map[string]interface{})
	if not["match"].(map[string]interface{})["geoip"] == nil || not["policy"] != "Proxy" {
		t.Fatalf("NOT = %#v", not)
	}
	for i, kind := range []string{"asn", "ip_cidr6"} {
		if rules[i+2].(map[string]interface{})[kind].(map[string]interface{})["no_resolve"] != true {
			t.Fatalf("missing no_resolve: %#v", rules[i+2])
		}
	}
}

func TestMalformedLogicalRulesAreDroppedAsAWhole(t *testing.T) {
	for _, rule := range []string{
		"AND,((DOMAIN,example.com),(PROCESS-NAME,app)),Proxy",
		"AND,((DOMAIN,example.com),),Proxy",
		"AND,((DOMAIN,example.com)),",
		"NOT,((DOMAIN,a),(DOMAIN,b)),Proxy",
		"OR,((DOMAIN,a),Proxy",
	} {
		got, warnings := convertDocument(t, "rules:\n  - "+rule+"\n")
		if len(warnings) != 1 || got["rules"] != nil {
			t.Fatalf("%s: warnings = %v, rules = %#v", rule, warnings, got["rules"])
		}
	}
}

func TestDNSUnsupportedPoliciesWarnWithoutEmittingInvalidRules(t *testing.T) {
	got, warnings := convertDocument(t, `
dns:
  proxy-server-nameserver: [1.1.1.1]
  nameserver-policy:
    geosite:cn: system
    rule-set:missing: system
    rule-set:ClashOnly: system
rule-providers:
  ClashOnly: {url: "https://example.com/clash.yaml"}
`)
	if len(warnings) != 5 || got["dns"] != nil {
		t.Fatalf("warnings = %v, DNS = %#v", warnings, got["dns"])
	}
}

func TestSourcePortRuleIsNotConvertedToDestinationPort(t *testing.T) {
	got, warnings := convertDocument(t, "rules:\n  - SRC-PORT,1234,REJECT\n  - MATCH,DIRECT\n")
	if len(warnings) != 1 || !strings.Contains(warnings[0], "SRC-PORT") {
		t.Fatalf("warnings = %v", warnings)
	}
	rules := got["rules"].([]interface{})
	if len(rules) != 1 || rules[0].(map[string]interface{})["default"] == nil {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestMissingProviderUsesValidFallbackGroup(t *testing.T) {
	got, warnings := convertDocument(t, `proxy-groups:
  - {name: Empty, type: fallback, use: [missing]}
`)
	if len(warnings) != 1 {
		t.Fatal(warnings)
	}
	group := got["policy_groups"].([]interface{})[0].(map[string]interface{})["fallback"].(map[string]interface{})
	if !reflect.DeepEqual(group["policies"], []interface{}{"DIRECT"}) {
		t.Fatalf("group = %#v", group)
	}
}
