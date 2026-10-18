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

func TestConvertGeneralEmitsAllowWifiAccessExplicitly(t *testing.T) {
	disabled := convertGeneral(map[string]interface{}{"allow-lan": false})
	for _, want := range []string{
		"allow-wifi-access = false",
		"wifi-access-http-port = 7222",
		"wifi-access-socks5-port = 7221",
	} {
		if !strings.Contains(disabled, want) {
			t.Fatalf("convertGeneral() missing %q for allow-lan: false:\n%s", want, disabled)
		}
	}

	enabled := convertGeneral(map[string]interface{}{"allow-lan": true})
	if !strings.Contains(enabled, "allow-wifi-access = true") {
		t.Fatalf("convertGeneral() missing allow-wifi-access = true:\n%s", enabled)
	}
}

func TestConvertHostsSkipsPlainHostPortServer(t *testing.T) {
	got := convertHosts(map[string]interface{}{
		"*.example.com": "127.0.0.1",
	}, map[string]interface{}{
		"cdn.example.com": []interface{}{
			"dn-hk.example.com:1066",
			"https://dn-jp.example.com/dns-query",
		},
	})

	if !strings.Contains(got, "cdn.example.com = server:https://dn-jp.example.com/dns-query") {
		t.Fatalf("convertHosts() did not fall back to the DoH server:\n%s", got)
	}
	if strings.Contains(got, "1066") {
		t.Fatalf("convertHosts() emitted unsupported host:port upstream:\n%s", got)
	}
}

func TestConvertHostsWarnsWhenNoCompatibleServer(t *testing.T) {
	got := convertHosts(nil, map[string]interface{}{
		"cdn.example.com": "dn-hk.example.com:1066",
	})

	if !strings.Contains(got, "# [WARNING] no Loon-compatible DNS server for cdn.example.com") {
		t.Fatalf("convertHosts() missing warning:\n%s", got)
	}
	if strings.Contains(got, "cdn.example.com = server:") {
		t.Fatalf("convertHosts() emitted invalid host mapping:\n%s", got)
	}
}

func TestConvertHostsAcceptsSystemAndIP(t *testing.T) {
	got := convertHosts(nil, map[string]interface{}{
		"*.ip.example.com":     "223.5.5.5",
		"*.system.example.com": "system",
		"*.v6.example.com":     "[2001:db8::1]",
	})

	for _, want := range []string{
		"*.ip.example.com = server:223.5.5.5",
		"*.system.example.com = server:system",
		"*.v6.example.com = server:2001:db8::1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("convertHosts() missing %q:\n%s", want, got)
		}
	}
}

func TestConvertRulesMapsNestedLogicTokens(t *testing.T) {
	ruleText, _ := convertRulesAndRemoteRules([]interface{}{
		"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
		"NOT,((NETWORK,TCP)),DIRECT",
	}, nil, nil)

	for _, want := range []string{
		"AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT",
		"NOT,((PROTOCOL,TCP)),DIRECT",
	} {
		if !strings.Contains(ruleText, want) {
			t.Fatalf("logic rule output missing %q:\n%s", want, ruleText)
		}
	}
	if strings.Contains(ruleText, "NETWORK") || strings.Contains(ruleText, "DST-PORT") {
		t.Fatalf("logic rule still contains Clash-only tokens:\n%s", ruleText)
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

func TestConvertRemoteFiltersWithExcludeFilter(t *testing.T) {
	groups := []map[string]interface{}{
		{
			"name":           "GroupA",
			"use":            []interface{}{"sub1"},
			"exclude-filter": "(?i)traffic|expire",
		},
		{
			"name":           "GroupB",
			"use":            []interface{}{"sub1"},
			"filter":         "HK",
			"exclude-filter": "0.1x",
		},
	}

	got := convertRemoteFilters(groups, nil)
	wantA := `GroupA_Filter = NameRegex,sub1,FilterKey = "^(?i)(?!.*(traffic|expire)).*$"`
	wantB := `GroupB_Filter = NameRegex,sub1,FilterKey = "^(?=.*(?:HK))(?!.*(?i)(0.1x)).*$"`

	if !strings.Contains(got, wantA) {
		t.Fatalf("convertRemoteFilters() missing %s in:\n%s", wantA, got)
	}
	if !strings.Contains(got, wantB) {
		t.Fatalf("convertRemoteFilters() missing %s in:\n%s", wantB, got)
	}
}
