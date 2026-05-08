package loon

import (
	"strings"
	"testing"
)

func TestConvertGeneralHandlesDoh3AndRealIPWildcard(t *testing.T) {
	got := convertGeneral(map[string]interface{}{
		"dns": map[string]interface{}{
			"nameserver":     []interface{}{"h3://dns.example.com/dns-query"},
			"fake-ip-filter": []interface{}{"*", "+.lan"},
		},
	})

	if !strings.Contains(got, "doh3-server = h3://dns.example.com/dns-query") {
		t.Fatalf("convertGeneral() missing doh3-server:\n%s", got)
	}
	if !strings.Contains(got, "real-ip = *.lan") {
		t.Fatalf("convertGeneral() missing converted real-ip wildcard:\n%s", got)
	}
	if strings.Contains(got, "+.lan") {
		t.Fatalf("convertGeneral() still contains Clash wildcard:\n%s", got)
	}
}

func TestConvertRulesKeepsLogicRulesAndMapsNetwork(t *testing.T) {
	ruleText, _ := convertRulesAndRemoteRules([]interface{}{
		"AND,((DOMAIN-SUFFIX,example.com),(PROTOCOL,HTTP)),Proxy",
		"NETWORK,UDP,Reject",
		"MATCH,DIRECT",
	}, nil, nil)

	for _, want := range []string{
		"AND,((DOMAIN-SUFFIX,example.com),(PROTOCOL,HTTP)),Proxy",
		"PROTOCOL,UDP,Reject",
		"FINAL,DIRECT",
	} {
		if !strings.Contains(ruleText, want) {
			t.Fatalf("rule output missing %q:\n%s", want, ruleText)
		}
	}
	if strings.Contains(ruleText, "Unsupported rule type in Loon: AND") {
		t.Fatalf("logic rule was marked unsupported:\n%s", ruleText)
	}
}

func TestConvertTrojanHTTPTransport(t *testing.T) {
	got := convertTrojan(map[string]interface{}{
		"name":     "trojan-http",
		"server":   "proxy.example.com",
		"port":     443,
		"password": "secret",
		"network":  "http",
		"http-opts": map[string]interface{}{
			"path": []interface{}{"/h2"},
			"host": []interface{}{"host.example.com"},
		},
	})

	for _, want := range []string{"transport=http", "path=/h2", "host=host.example.com"} {
		if !strings.Contains(got, want) {
			t.Fatalf("convertTrojan() missing %q: %s", want, got)
		}
	}
}

func TestConvertVlessHTTPTransport(t *testing.T) {
	got := convertVless(map[string]interface{}{
		"name":    "vless-http",
		"server":  "proxy.example.com",
		"port":    443,
		"uuid":    "00000000-0000-0000-0000-000000000000",
		"network": "http",
		"http-opts": map[string]interface{}{
			"path": []interface{}{"/vless"},
			"host": []interface{}{"host.example.com"},
		},
	})

	for _, want := range []string{"transport=http", "path=/vless", "host=host.example.com"} {
		if !strings.Contains(got, want) {
			t.Fatalf("convertVless() missing %q: %s", want, got)
		}
	}
}

func TestConvertWireGuard(t *testing.T) {
	got := convertWireGuard(map[string]interface{}{
		"name":           "wg",
		"server":         "wg.example.com",
		"port":           51820,
		"ip":             "172.16.0.2/32",
		"private-key":    "private",
		"public-key":     "public",
		"pre-shared-key": "psk",
		"reserved":       []interface{}{1, 2, 3},
		"allowed-ips":    []interface{}{"0.0.0.0/0", "::/0"},
		"mtu":            1280,
		"dns":            []interface{}{"1.1.1.1"},
		"keepalive":      45,
	})

	for _, want := range []string{
		"wg = WireGuard",
		"interface-ip=172.16.0.2/32",
		`private-key="private"`,
		"mtu=1280",
		"dns=1.1.1.1",
		"keeyalive=45",
		`public-key="public"`,
		`preshared-key="psk"`,
		"reserved=[1,2,3]",
		`allowed-ips="0.0.0.0/0,::/0"`,
		"endpoint=wg.example.com:51820",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("convertWireGuard() missing %q: %s", want, got)
		}
	}
}

func TestConvertAnyTLS(t *testing.T) {
	got := convertAnyTLS(map[string]interface{}{
		"name":             "any",
		"server":           "any.example.com",
		"port":             443,
		"password":         "secret",
		"servername":       "sni.example.com",
		"skip-cert-verify": true,
	})

	for _, want := range []string{
		"any = AnyTLS,any.example.com,443",
		`password="secret"`,
		"sni=sni.example.com",
		"skip-cert-verify=true",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("convertAnyTLS() missing %q: %s", want, got)
		}
	}
}
