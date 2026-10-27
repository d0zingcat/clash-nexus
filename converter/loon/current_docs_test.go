package loon

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func convertCurrentLoonDocument(t *testing.T, input string) (string, []string) {
	t.Helper()
	var config map[string]interface{}
	if err := yaml.Unmarshal([]byte(input), &config); err != nil {
		t.Fatal(err)
	}
	out, warnings, err := New().Convert(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), warnings
}

func TestCurrentLoonNodeDNSForLocalAndSubscriptionNodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[General]\ndns-server = 1.1.1.1\n[Proxy]\nRemote = AnyTLS,remote.example.com,443,\"password\"\n"))
	}))
	defer server.Close()
	out, warnings := convertCurrentLoonDocument(t, `
dns:
  nameserver: ["https://global.example.com/dns-query"]
  proxy-server-nameserver: [223.5.5.5, "h3://node.example.com/dns-query"]
proxies:
  - {name: Local, type: socks5, server: local.example.com, port: 443, tls: true, sni: sni.example.com, fingerprint: aabb, client-fingerprint: chrome147, ip-version: ipv6-prefer, tfo: true}
proxy-providers:
  Remote: {type: http, url: "`+server.URL+`"}
`)
	if len(warnings) != 0 {
		t.Fatal(warnings)
	}
	for _, want := range []string{
		`server-dns="223.5.5.5,h3://node.example.com/dns-query"`,
		"over-tls=true", "sni=sni.example.com", "tls-cert-sha256=aabb", "tls-profile=chrome147", "ip-mode=prefer-v6", "fast-open=true",
		"doh-server = https://global.example.com/dns-query",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	if strings.Count(out, `server-dns="223.5.5.5,h3://node.example.com/dns-query"`) != 2 {
		t.Fatal("node DNS should be emitted on both local and remote entries")
	}
	if strings.Contains(out, "# [WARNING]") {
		t.Fatalf("native Loon subscription was incorrectly rejected:\n%s", out)
	}
}

func TestCurrentLoonRejectsUnrepresentableNodeDNS(t *testing.T) {
	for _, server := range []string{"tls://1.1.1.1", "https://dns.example.com/dns-query#Proxy", "not-a-server"} {
		out, warnings := convertCurrentLoonDocument(t, `
dns:
  proxy-server-nameserver: [1.1.1.1, "`+server+`"]
proxies:
  - {name: Local, type: anytls, server: example.com, port: 443, password: test}
`)
		if len(warnings) != 1 || strings.Contains(out, "server-dns=") {
			t.Fatalf("%s: warnings=%v, output=%s", server, warnings, out)
		}
	}
}

func TestCurrentLoonHysteria2AndAnyTLSOptions(t *testing.T) {
	out, warnings := convertCurrentLoonDocument(t, `proxies:
  - {name: HY2, type: hysteria2, server: example.com, port: 443, password: test, obfs: salamander, obfs-password: "obfs,password", ports: "20000-20100", hop-interval: 30, down: "1 Gbps", alpn: [h3], tfo: true}
  - {name: Any, type: anytls, server: example.com, port: 443, password: test, idle-session-timeout: 45}
`)
	if len(warnings) != 0 {
		t.Fatal(warnings)
	}
	for _, want := range []string{`salamander-password="obfs,password"`, `server-ports="20000:20100"`, "hop-interval=30", "download-bandwidth=1000", `alpn="h3"`, "fast-open=true", "idle-session-timeout=45"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
}

func TestCurrentLoonUnsupportedTransportsArePruned(t *testing.T) {
	out, warnings := convertCurrentLoonDocument(t, `proxies:
  - {name: OK, type: anytls, server: example.com, port: 443, password: test}
  - {name: GRPC, type: vless, network: grpc}
  - {name: TrojanHTTP, type: trojan, network: http}
  - {name: Gecko, type: hysteria2, obfs: gecko}
  - {name: RandomHop, type: hysteria2, hop-interval: "15-30"}
proxy-groups:
  - {name: Choose, type: select, proxies: [OK, GRPC, TrojanHTTP, Gecko, RandomHop]}
`)
	if !strings.Contains(out, "Choose = select,OK\n") || len(warnings) != 8 {
		t.Fatalf("warnings=%v, output=%s", warnings, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "GRPC =") || strings.HasPrefix(line, "TrojanHTTP =") || strings.HasPrefix(line, "Gecko =") {
			t.Fatalf("unrepresentable node was emitted: %s", line)
		}
	}
}

func TestCurrentLoonWireGuardPeersAndIPv6(t *testing.T) {
	out, warnings := convertCurrentLoonDocument(t, `proxies:
  - name: WG
    type: wireguard
    ip: 172.16.0.2
    ipv6: "fd00::2"
    private-key: private
    persistent-keepalive: 0
    dns: [1.1.1.1, "2606:4700:4700::1111"]
    peers:
      - {server: "2001:db8::1", port: 51820, public-key: public1, reserved: AQID, allowed-ips: ["0.0.0.0/0"]}
      - {server: wg.example.com, port: 51820, public-key: public2, pre-shared-key: psk, allowed-ips: ["::/0"]}
`)
	if len(warnings) != 0 {
		t.Fatal(warnings)
	}
	for _, want := range []string{"interface-ipv6=fd00::2", "keepalive=0", "dnsv6=2606:4700:4700::1111", "endpoint=[2001:db8::1]:51820", "endpoint=wg.example.com:51820", "reserved=[1,2,3]", `public-key="public1"`, `public-key="public2"`, `preshared-key="psk"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "keeyalive=") {
		t.Fatal("legacy misspelling emitted")
	}
}

func TestCurrentLoonWildcardRoutesAndLoadBalance(t *testing.T) {
	out, warnings := convertCurrentLoonDocument(t, `tun:
  enable: true
  route-address: [10.7.0.9/24, 10.7.0.0/24, "fd00::/64", 10.8.0.1]
rules:
  - DOMAIN-WILDCARD,api?.example.com,DIRECT
  - DOMAIN-WILDCARD,node[0-9].example.com,DIRECT
proxy-groups:
  - {name: Balance, type: load-balance, proxies: [DIRECT], timeout: 2500, strategy: consistent-hashing}
`)
	if len(warnings) != 0 {
		t.Fatal(warnings)
	}
	for _, want := range []string{"include-tun = 10.7.0.0/24\n", "DOMAIN-WILDCARD,api?.example.com,DIRECT", "DOMAIN-WILDCARD,node[0-9].example.com,DIRECT", "max-timeout = 2500,algorithm = PCC", "include-tun requires IPv4 CIDR; skipping fd00::/64"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Unsupported rule type in Loon: DOMAIN-WILDCARD") {
		t.Fatal("wildcard was dropped")
	}
}

func TestCurrentLoonTextSubscriptionFormats(t *testing.T) {
	for _, content := range []string{
		"anytls://password@example.com:443#Node",
		"Node = AnyTLS,example.com,443,\"password\"",
		"[General]\ndns-server = 1.1.1.1\n[Host]\na.example.com = 1.1.1.1\n[Proxy]\nNode = AnyTLS,example.com,443,\"password\"",
	} {
		for _, body := range []string{content, base64.StdEncoding.EncodeToString([]byte(content))} {
			if warning := validateSubscriptionContent([]byte(body)); warning != "" {
				t.Fatalf("valid subscription rejected: %s", warning)
			}
		}
	}
	for _, body := range []string{"[Proxy]\nNode = AnyTLS,example.com,443,\"password\"\n[Rule]\nFINAL,DIRECT", "[General]\ndns-server = 1.1.1.1"} {
		for _, content := range []string{body, base64.StdEncoding.EncodeToString([]byte(body))} {
			if validateSubscriptionContent([]byte(content)) == "" {
				t.Fatal("non-subscription config accepted")
			}
		}
	}
}

func TestLoonBandwidthUnits(t *testing.T) {
	for input, want := range map[string]string{"100": "100", "1 Gbps": "1000", "500 kbps": "0.5", "2000000 bps": "2"} {
		if got, ok := loonBandwidthMbps(input); !ok || got != want {
			t.Errorf("%s: %s, %v; want %s", input, got, ok, want)
		}
	}
}
