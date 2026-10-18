package singbox

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"clash-nexus/converter"
)

func TestConverterMetadataAndEmptyConfig(t *testing.T) {
	var _ converter.Converter = New()
	c := New()
	if got := c.Name(); got != "singbox" {
		t.Fatalf("Name() = %q, want singbox", got)
	}
	if got := c.DefaultExtension(); got != ".json" {
		t.Fatalf("DefaultExtension() = %q, want .json", got)
	}

	out, warnings, err := c.Convert(map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	config := decodeJSON(t, out)
	outbounds := outboundsByTag(config)
	if _, ok := outbounds["DIRECT"]; !ok {
		t.Fatalf("missing DIRECT outbound: %s", out)
	}
	if _, ok := outbounds["REJECT"]; !ok {
		t.Fatalf("missing REJECT outbound: %s", out)
	}
	route := config["route"].(map[string]interface{})
	if route["final"] != "DIRECT" {
		t.Fatalf("route.final = %v, want DIRECT", route["final"])
	}
}

func TestConvertCoreConfig(t *testing.T) {
	input := map[string]interface{}{
		"log-level":           "warning",
		"mode":                "rule",
		"mixed-port":          7890,
		"allow-lan":           true,
		"external-controller": "127.0.0.1:9090",
		"secret":              "secret",
		"hosts": map[string]interface{}{
			"router.lan": "192.168.1.1",
		},
		"dns": map[string]interface{}{
			"enable":             true,
			"default-nameserver": []interface{}{"1.1.1.1"},
			"nameserver":         []interface{}{"https://dns.google/dns-query"},
			"fallback":           []interface{}{"tls://1.0.0.1"},
			"nameserver-policy": map[string]interface{}{
				"+.internal.example": "1.1.1.1",
			},
			"enhanced-mode": "fake-ip",
			"fake-ip-range": "198.18.0.1/16",
			"fake-ip-filter": []interface{}{
				"+.lan",
				"example.com",
			},
		},
		"proxies": []interface{}{
			map[string]interface{}{
				"name": "ss-node", "type": "ss", "server": "ss.example.com", "port": 8388,
				"cipher": "aes-256-gcm", "password": "pass", "udp": true,
			},
			map[string]interface{}{
				"name": "trojan-node", "type": "trojan", "server": "trojan.example.com", "port": 443,
				"password": "pass", "sni": "trojan.example.com",
			},
		},
		"proxy-groups": []interface{}{
			map[string]interface{}{
				"name": "Proxy", "type": "select", "proxies": []interface{}{"ss-node", "trojan-node"},
			},
			map[string]interface{}{
				"name": "Auto", "type": "url-test",
				"proxies": []interface{}{"Proxy", "ss-node"},
				"url":     "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50,
			},
		},
		"rule-providers": map[string]interface{}{
			"MySet": map[string]interface{}{
				"type": "http", "behavior": "domain", "format": "binary",
				"url": "https://example.com/rules/my-set.srs", "interval": 86400,
			},
		},
		"rules": []interface{}{
			"DOMAIN-SUFFIX,example.com,Proxy",
			"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
			"GEOIP,CN,DIRECT",
			"RULE-SET,MySet,Proxy",
			"MATCH,Auto",
		},
	}

	out, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none; output=%s", warnings, out)
	}
	config := decodeJSON(t, out)

	log := config["log"].(map[string]interface{})
	if log["level"] != "warn" {
		t.Fatalf("log.level = %v, want warn", log["level"])
	}
	inbounds := config["inbounds"].([]interface{})
	mixed := inbounds[0].(map[string]interface{})
	if mixed["type"] != "mixed" || mixed["listen"] != "0.0.0.0" || mixed["listen_port"] != float64(7890) {
		t.Fatalf("unexpected mixed inbound: %#v", mixed)
	}

	outbounds := outboundsByTag(config)
	if outbounds["ss-node"]["type"] != "shadowsocks" {
		t.Fatalf("ss outbound type = %v", outbounds["ss-node"]["type"])
	}
	if outbounds["trojan-node"]["tls"] == nil {
		t.Fatalf("trojan must have TLS: %#v", outbounds["trojan-node"])
	}
	proxyGroup := outbounds["Proxy"]
	if proxyGroup["type"] != "selector" {
		t.Fatalf("Proxy type = %v", proxyGroup["type"])
	}
	if got := stringSlice(proxyGroup["outbounds"]); !reflect.DeepEqual(got, []string{"ss-node", "trojan-node"}) {
		t.Fatalf("Proxy outbounds = %v", got)
	}
	autoGroup := outbounds["Auto"]
	if autoGroup["type"] != "urltest" || autoGroup["interval"] != "5m" || autoGroup["tolerance"] != float64(50) {
		t.Fatalf("unexpected Auto group: %#v", autoGroup)
	}

	route := config["route"].(map[string]interface{})
	if route["final"] != "Auto" {
		t.Fatalf("route.final = %v, want Auto", route["final"])
	}
	ruleSets := route["rule_set"].([]interface{})
	ruleSetTags := map[string]string{}
	for _, value := range ruleSets {
		def := value.(map[string]interface{})
		ruleSetTags[def["tag"].(string)] = def["type"].(string)
	}
	if ruleSetTags["MySet"] != "remote" || ruleSetTags["geoip-cn"] != "remote" {
		t.Fatalf("rule sets = %#v", ruleSetTags)
	}
	rules := route["rules"].([]interface{})
	assertRuleField(t, rules, "domain_suffix", "example.com", "Proxy")
	assertRuleField(t, rules, "ip_cidr", "10.0.0.0/8", "DIRECT")
	assertRuleField(t, rules, "rule_set", "geoip-cn", "DIRECT")
	assertRuleField(t, rules, "rule_set", "MySet", "Proxy")

	dns := config["dns"].(map[string]interface{})
	if dns["strategy"] != "ipv4_only" {
		t.Fatalf("dns.strategy = %v", dns["strategy"])
	}
	servers := dns["servers"].([]interface{})
	serverTypes := map[string]string{}
	for _, value := range servers {
		server := value.(map[string]interface{})
		serverTypes[server["tag"].(string)] = server["type"].(string)
	}
	if serverTypes["bootstrap"] != "udp" || serverTypes["dns"] != "https" || serverTypes["dns-2"] != "tls" {
		t.Fatalf("dns server types = %#v", serverTypes)
	}
	if serverTypes["hosts"] != "hosts" || serverTypes["fakeip"] != "fakeip" {
		t.Fatalf("dns server types = %#v", serverTypes)
	}
	if dns["final"] != "dns" {
		t.Fatalf("dns.final = %v, want dns", dns["final"])
	}

	experimental := config["experimental"].(map[string]interface{})
	clashAPI := experimental["clash_api"].(map[string]interface{})
	if clashAPI["external_controller"] != "127.0.0.1:9090" || clashAPI["secret"] != "secret" {
		t.Fatalf("clash_api = %#v", clashAPI)
	}
}

func TestConvertProxyProtocols(t *testing.T) {
	input := map[string]interface{}{
		"proxies": []interface{}{
			map[string]interface{}{
				"name": "ss-obfs", "type": "ss", "server": "ss.example.com", "port": 8388,
				"cipher": "aes-256-gcm", "password": "pass", "udp": true,
				"plugin": "obfs", "plugin-opts": map[string]interface{}{"mode": "http", "host": "obfs.example.com"},
			},
			map[string]interface{}{
				"name": "vmess-ws", "type": "vmess", "server": "vmess.example.com", "port": 443,
				"uuid": "uuid", "cipher": "auto", "alterId": 0, "tls": true, "servername": "cdn.example.com",
				"network": "ws", "ws-opts": map[string]interface{}{
					"path":    "/ws",
					"headers": map[string]interface{}{"Host": "cdn.example.com"},
				},
			},
			map[string]interface{}{
				"name": "vless-reality", "type": "vless", "server": "vless.example.com", "port": 443,
				"uuid": "uuid", "flow": "xtls-rprx-vision", "tls": true, "servername": "www.example.com",
				"client-fingerprint": "chrome",
				"reality-opts":       map[string]interface{}{"public-key": "pub", "short-id": "abcd"},
				"network":            "grpc", "grpc-opts": map[string]interface{}{"grpc-service-name": "svc"},
			},
			map[string]interface{}{
				"name": "trojan-ws", "type": "trojan", "server": "trojan.example.com", "port": 443,
				"password": "pass", "sni": "trojan.example.com", "network": "ws",
				"ws-opts": map[string]interface{}{"path": "/trojan"},
			},
			map[string]interface{}{
				"name": "hy2", "type": "hysteria2", "server": "hy2.example.com", "port": 443,
				"password": "pass", "sni": "hy2.example.com", "ports": "1000-2000",
				"hop-interval": 30, "up": "100 Mbps", "down": "200 Mbps",
				"obfs": "salamander", "obfs-password": "obfs-pass",
			},
			map[string]interface{}{
				"name": "tuic", "type": "tuic", "server": "tuic.example.com", "port": 443,
				"uuid": "uuid", "password": "pass", "congestion-controller": "bbr",
				"udp-relay-mode": "quic", "reduce-rtt": true, "heartbeat-interval": 10,
				"alpn": []interface{}{"h3"},
			},
			map[string]interface{}{
				"name": "wg", "type": "wireguard", "server": "wg.example.com", "port": 51820,
				"ip": "10.0.0.2/32", "ipv6": "fd00::2/128",
				"private-key": "priv", "public-key": "pub", "preshared-key": "psk",
				"reserved": []interface{}{1, 2, 3}, "mtu": 1420,
			},
			map[string]interface{}{
				"name": "socks", "type": "socks5", "server": "socks.example.com", "port": 1080,
				"username": "user", "password": "pass", "udp": true,
			},
			map[string]interface{}{
				"name": "http", "type": "http", "server": "http.example.com", "port": 443,
				"username": "user", "password": "pass", "tls": true, "sni": "http.example.com",
			},
			map[string]interface{}{
				"name": "anytls", "type": "anytls", "server": "anytls.example.com", "port": 443,
				"password": "pass", "sni": "anytls.example.com",
			},
			map[string]interface{}{
				"name": "snell", "type": "snell", "server": "snell.example.com", "port": 443,
				"psk": "psk", "version": 4, "obfs-opts": map[string]interface{}{"mode": "http", "host": "bing.com"},
			},
			map[string]interface{}{
				"name": "unsupported-ssr", "type": "ssr", "server": "ssr.example.com", "port": 443,
			},
		},
	}

	out, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	config := decodeJSON(t, out)
	outbounds := outboundsByTag(config)

	if outbounds["ss-obfs"]["plugin"] != "obfs-local" {
		t.Fatalf("ss plugin = %v", outbounds["ss-obfs"]["plugin"])
	}
	vmess := outbounds["vmess-ws"]
	transport := vmess["transport"].(map[string]interface{})
	if transport["type"] != "ws" || transport["path"] != "/ws" {
		t.Fatalf("vmess transport = %#v", transport)
	}
	tls := vmess["tls"].(map[string]interface{})
	if tls["server_name"] != "cdn.example.com" {
		t.Fatalf("vmess tls = %#v", tls)
	}
	vless := outbounds["vless-reality"]
	vlessTLS := vless["tls"].(map[string]interface{})
	reality := vlessTLS["reality"].(map[string]interface{})
	if reality["public_key"] != "pub" || reality["short_id"] != "abcd" {
		t.Fatalf("vless reality = %#v", reality)
	}
	if vlessTLS["utls"].(map[string]interface{})["fingerprint"] != "chrome" {
		t.Fatalf("vless utls = %#v", vlessTLS["utls"])
	}
	if vless["transport"].(map[string]interface{})["service_name"] != "svc" {
		t.Fatalf("vless transport = %#v", vless["transport"])
	}
	trojanTransport := outbounds["trojan-ws"]["transport"].(map[string]interface{})
	if trojanTransport["type"] != "ws" || trojanTransport["path"] != "/trojan" {
		t.Fatalf("trojan transport = %#v", trojanTransport)
	}

	hy2 := outbounds["hy2"]
	if hy2["server_ports"].([]interface{})[0] != "1000:2000" {
		t.Fatalf("hy2 server_ports = %#v", hy2["server_ports"])
	}
	if hy2["up_mbps"] != float64(100) || hy2["down_mbps"] != float64(200) {
		t.Fatalf("hy2 speeds = %#v", hy2)
	}
	if hy2["obfs"].(map[string]interface{})["type"] != "salamander" {
		t.Fatalf("hy2 obfs = %#v", hy2["obfs"])
	}

	tuic := outbounds["tuic"]
	if tuic["congestion_control"] != "bbr" || tuic["udp_relay_mode"] != "quic" || tuic["zero_rtt_handshake"] != true {
		t.Fatalf("tuic = %#v", tuic)
	}

	wg := endpointsByTag(config)["wg"]
	if wg == nil || wg["private_key"] != "priv" || wg["mtu"] != float64(1420) {
		t.Fatalf("wireguard endpoint = %#v", wg)
	}
	if len(wg["address"].([]interface{})) != 2 {
		t.Fatalf("wireguard address = %#v", wg["address"])
	}
	peer := wg["peers"].([]interface{})[0].(map[string]interface{})
	if peer["public_key"] != "pub" || peer["pre_shared_key"] != "psk" {
		t.Fatalf("wireguard peer = %#v", peer)
	}

	if outbounds["socks"]["version"] != "5" || outbounds["socks"]["username"] != "user" {
		t.Fatalf("socks = %#v", outbounds["socks"])
	}
	if outbounds["http"]["tls"] == nil {
		t.Fatalf("http tls = %#v", outbounds["http"])
	}
	if outbounds["anytls"]["tls"] == nil {
		t.Fatalf("anytls tls = %#v", outbounds["anytls"])
	}
	if outbounds["snell"]["version"] != float64(4) || outbounds["snell"]["obfs_mode"] != "http" {
		t.Fatalf("snell = %#v", outbounds["snell"])
	}
	if _, exists := outbounds["unsupported-ssr"]; exists {
		t.Fatalf("ssr outbound must be skipped")
	}
	if !containsWarning(warnings, `skipping proxy "unsupported-ssr": type "ssr"`) {
		t.Fatalf("warnings = %v", warnings)
	}
}

func TestRealityAddsDefaultUTLS(t *testing.T) {
	input := map[string]interface{}{
		"proxies": []interface{}{
			map[string]interface{}{
				"name": "reality", "type": "vless", "server": "reality.example.com", "port": 443,
				"uuid": "bf000d23-0752-40b4-affe-68f7707a9661", "tls": true,
				"servername": "www.example.com",
				"reality-opts": map[string]interface{}{
					"public-key": "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=",
					"short-id":   "abcd",
				},
			},
		},
		"rules": []interface{}{"MATCH,DIRECT"},
	}
	out, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	config := decodeJSON(t, out)
	tls := outboundsByTag(config)["reality"]["tls"].(map[string]interface{})
	utls, _ := tls["utls"].(map[string]interface{})
	if utls["fingerprint"] != "chrome" {
		t.Fatalf("utls = %#v, want chrome fingerprint", tls["utls"])
	}
	reality := tls["reality"].(map[string]interface{})
	if strings.Contains(reality["public_key"].(string), "=") {
		t.Fatalf("reality public_key must be unpadded: %v", reality["public_key"])
	}
}

func TestConvertWarnsForUnsupportedProviders(t *testing.T) {
	input := map[string]interface{}{
		"proxy-providers": map[string]interface{}{
			"provider": map[string]interface{}{"type": "http", "url": "https://example.com/sub.yaml"},
		},
		"proxy-groups": []interface{}{
			map[string]interface{}{"name": "ProviderGroup", "type": "select", "use": []interface{}{"provider"}},
		},
		"proxies": []interface{}{
			map[string]interface{}{"name": "ss-node", "type": "ss", "server": "ss.example.com", "port": 8388, "cipher": "aes-128-gcm", "password": "pass"},
		},
		"rule-providers": map[string]interface{}{
			"ClashSet": map[string]interface{}{
				"type": "http", "behavior": "domain", "url": "https://example.com/rules.yaml",
			},
		},
		"rules": []interface{}{
			"RULE-SET,ClashSet,DIRECT",
			"MATCH,DIRECT",
		},
	}
	_, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	for _, want := range []string{
		`proxy group "ProviderGroup": proxy-provider "provider" is not supported by sing-box`,
		`proxy-providers are not natively supported by sing-box`,
		`skipping rule provider "ClashSet"`,
		`skipping rule RULE-SET,ClashSet`,
	} {
		if !containsWarning(warnings, want) {
			t.Fatalf("warnings = %v, want %q", warnings, want)
		}
	}

	_, second, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("second Convert() error = %v", err)
	}
	if !reflect.DeepEqual(warnings, second) {
		t.Fatalf("warnings are not deterministic:\n%v\n%v", warnings, second)
	}
}

type mockFetcher struct {
	data []byte
}

func (m *mockFetcher) Fetch(ctx context.Context, provider map[string]interface{}, basePath string) ([]byte, error) {
	return m.data, nil
}

func TestConvertExpandsProxyProviders(t *testing.T) {
	input := map[string]interface{}{
		"proxy-providers": map[string]interface{}{
			"provider": map[string]interface{}{"type": "http", "url": "https://example.com/sub.yaml"},
		},
		"proxy-groups": []interface{}{
			map[string]interface{}{"name": "Proxy", "type": "select", "use": []interface{}{"provider"}},
		},
	}
	fetcher := &mockFetcher{data: []byte(`
proxies:
  - name: ExpandedNode
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: pass
`)}
	out, warnings, err := NewWithFetcher(fetcher).ConvertWithOptions(input, nil, converter.Options{ExpandProxyProviders: true})
	if err != nil {
		t.Fatalf("ConvertWithOptions() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	config := decodeJSON(t, out)
	outbounds := outboundsByTag(config)
	if _, ok := outbounds["ExpandedNode"]; !ok {
		t.Fatalf("missing expanded node: %s", out)
	}
	if got := stringSlice(outbounds["Proxy"]["outbounds"]); !reflect.DeepEqual(got, []string{"ExpandedNode"}) {
		t.Fatalf("Proxy outbounds = %v", got)
	}
}

func TestConvertLogicalAndWildcardRules(t *testing.T) {
	input := map[string]interface{}{
		"rules": []interface{}{
			"AND,((DOMAIN,example.com),(NETWORK,tcp)),DIRECT",
			"DOMAIN-WILDCARD,*.example.net,DIRECT",
			"MATCH,DIRECT",
		},
	}
	out, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
	config := decodeJSON(t, out)
	rules := config["route"].(map[string]interface{})["rules"].([]interface{})
	logical := rules[0].(map[string]interface{})
	if logical["type"] != "logical" || logical["mode"] != "and" {
		t.Fatalf("logical rule = %#v", logical)
	}
	if len(logical["rules"].([]interface{})) != 2 {
		t.Fatalf("logical sub-rules = %#v", logical["rules"])
	}
	wildcard := rules[1].(map[string]interface{})
	if got := stringSlice(wildcard["domain_regex"]); !reflect.DeepEqual(got, []string{"^.*\\.example\\.net$"}) {
		t.Fatalf("domain_regex = %v", got)
	}
}

func TestConvertSkipsNonIPHostsValues(t *testing.T) {
	input := map[string]interface{}{
		"hosts": map[string]interface{}{
			"alias.example": "target.example",
			"router.lan":    "192.168.1.1",
		},
	}
	out, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if !containsWarning(warnings, `hosts entry "alias.example"`) {
		t.Fatalf("warnings = %v, want non-IP hosts warning", warnings)
	}
	config := decodeJSON(t, out)
	servers := config["dns"].(map[string]interface{})["servers"].([]interface{})
	var hostsServer map[string]interface{}
	for _, value := range servers {
		server := value.(map[string]interface{})
		if server["type"] == "hosts" {
			hostsServer = server
		}
	}
	if hostsServer == nil {
		t.Fatalf("missing hosts server: %#v", servers)
	}
	predefined := hostsServer["predefined"].(map[string]interface{})
	if _, exists := predefined["alias.example"]; exists {
		t.Fatalf("non-IP host must be skipped: %#v", predefined)
	}
	if predefined["router.lan"] != "192.168.1.1" {
		t.Fatalf("IP host = %#v", predefined["router.lan"])
	}
}

func TestConvertSkipsNilRuleEntries(t *testing.T) {
	input := map[string]interface{}{
		"rules": []interface{}{nil, "MATCH,DIRECT"},
	}
	_, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
}

func TestConvertFakeIPDisabledByCatchAllFilter(t *testing.T) {
	input := map[string]interface{}{
		"dns": map[string]interface{}{
			"enable":         true,
			"nameserver":     []interface{}{"1.1.1.1"},
			"enhanced-mode":  "fake-ip",
			"fake-ip-filter": []interface{}{"*"},
		},
	}
	out, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if !containsWarning(warnings, "fake-ip is not generated") {
		t.Fatalf("warnings = %v", warnings)
	}
	config := decodeJSON(t, out)
	servers := config["dns"].(map[string]interface{})["servers"].([]interface{})
	for _, value := range servers {
		if value.(map[string]interface{})["type"] == "fakeip" {
			t.Fatalf("fakeip server must not be generated: %#v", servers)
		}
	}
}

func decodeJSON(t *testing.T, data []byte) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; content=%s", err, data)
	}
	return out
}

func outboundsByTag(config map[string]interface{}) map[string]map[string]interface{} {
	return itemsByTag(config["outbounds"])
}

func endpointsByTag(config map[string]interface{}) map[string]map[string]interface{} {
	return itemsByTag(config["endpoints"])
}

func itemsByTag(raw interface{}) map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	values, _ := raw.([]interface{})
	for _, value := range values {
		item, _ := value.(map[string]interface{})
		if item == nil {
			continue
		}
		if tag, ok := item["tag"].(string); ok {
			out[tag] = item
		}
	}
	return out
}

func stringSlice(value interface{}) []string {
	switch v := value.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, item.(string))
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}

func assertRuleField(t *testing.T, rules []interface{}, field, value, outbound string) {
	t.Helper()
	for _, raw := range rules {
		rule, _ := raw.(map[string]interface{})
		if rule == nil {
			continue
		}
		if got := stringSlice(rule[field]); len(got) == 0 || got[0] != value {
			continue
		}
		if rule["outbound"] == outbound {
			return
		}
	}
	t.Fatalf("no rule with %s=%s and outbound=%s in %#v", field, value, outbound, rules)
}

func containsWarning(warnings []string, want string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, want) {
			return true
		}
	}
	return false
}
