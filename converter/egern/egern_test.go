package egern

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConvertMixedPortDoesNotReuseSocksPort(t *testing.T) {
	config := map[string]interface{}{
		"mixed-port": 7890,
	}

	content, _, err := New().Convert(config, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var got map[string]interface{}
	if err := yaml.Unmarshal(content, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got["http_port"] != 7890 {
		t.Fatalf("http_port = %#v, want 7890", got["http_port"])
	}
	if _, ok := got["socks_port"]; ok {
		t.Fatalf("socks_port was generated for mixed-port: %#v", got["socks_port"])
	}
}

func TestConvertDNSUsesOfficialWildcardFields(t *testing.T) {
	config := map[string]interface{}{
		"dns": map[string]interface{}{
			"default-nameserver": []interface{}{"223.5.5.5"},
			"nameserver":         []interface{}{"https://8.8.8.8/dns-query"},
			"fake-ip-filter":     []interface{}{"*", "+.lan"},
		},
	}

	content, _, err := New().Convert(config, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var got map[string]interface{}
	if err := yaml.Unmarshal(content, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	realIPDomains, ok := got["real_ip_domains"].([]interface{})
	if !ok || len(realIPDomains) != 1 || realIPDomains[0] != "*.lan" {
		t.Fatalf("real_ip_domains = %#v, want [*.lan]", got["real_ip_domains"])
	}

	dnsCfg := got["dns"].(map[string]interface{})
	forward := dnsCfg["forward"].([]interface{})
	catchAll := forward[len(forward)-1].(map[string]interface{})
	if _, ok := catchAll["domain_wildcard"]; !ok {
		t.Fatalf("catch-all forward = %#v, want domain_wildcard", catchAll)
	}
	if _, ok := catchAll["wildcard"]; ok {
		t.Fatalf("catch-all forward still uses deprecated wildcard field: %#v", catchAll)
	}
}

func TestConvertDNSNameserverPolicyKeepsDedicatedServerAndRuleSet(t *testing.T) {
	config := map[string]interface{}{
		"dns": map[string]interface{}{
			"default-nameserver": []interface{}{"223.5.5.5"},
			"nameserver-policy": map[string]interface{}{
				"+.example.com":   "https://1.1.1.1/dns-query",
				"rule-set:Google": "system",
			},
		},
		"rule-providers": map[string]interface{}{
			"Google": map[string]interface{}{
				"url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google.yaml",
			},
		},
	}

	content, _, err := New().Convert(config, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var got map[string]interface{}
	if err := yaml.Unmarshal(content, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	dnsCfg := got["dns"].(map[string]interface{})
	forward := dnsCfg["forward"].([]interface{})

	var foundDedicatedDNS bool
	var foundRuleSet bool
	for _, raw := range forward {
		rule := raw.(map[string]interface{})
		if domainSuffix, ok := rule["domain_suffix"].(map[string]interface{}); ok {
			if domainSuffix["match"] == "example.com" && domainSuffix["value"] == "https://1.1.1.1/dns-query" {
				foundDedicatedDNS = true
			}
		}
		if proxyRuleSet, ok := rule["proxy_rule_set"].(map[string]interface{}); ok {
			if proxyRuleSet["value"] == "bootstrap" && strings.Contains(proxyRuleSet["match"].(string), "/rule/Surge/Google/Google.list") {
				foundRuleSet = true
			}
		}
	}
	if !foundDedicatedDNS {
		t.Fatalf("forward = %#v, want domain_suffix using dedicated DNS server", forward)
	}
	if !foundRuleSet {
		t.Fatalf("forward = %#v, want proxy_rule_set using converted provider URL", forward)
	}
}

func TestConvertVmessWSSPreservesHostHeaderAndSNI(t *testing.T) {
	config := map[string]interface{}{
		"proxies": []interface{}{
			map[string]interface{}{
				"name":       "vmess-wss",
				"type":       "vmess",
				"server":     "proxy.example.com",
				"port":       443,
				"uuid":       "00000000-0000-0000-0000-000000000000",
				"cipher":     "auto",
				"network":    "ws",
				"tls":        true,
				"servername": "sni.example.com",
				"ws-opts": map[string]interface{}{
					"path": "/ws",
					"headers": map[string]interface{}{
						"Host": "host.example.com",
					},
				},
			},
		},
	}

	content, _, err := New().Convert(config, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var got map[string]interface{}
	if err := yaml.Unmarshal(content, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	proxies := got["proxies"].([]interface{})
	vmess := proxies[0].(map[string]interface{})["vmess"].(map[string]interface{})
	wss := vmess["transport"].(map[string]interface{})["wss"].(map[string]interface{})
	headers := wss["headers"].(map[string]interface{})

	if headers["Host"] != "host.example.com" {
		t.Fatalf("wss.headers.Host = %#v, want host.example.com", headers["Host"])
	}
	if wss["sni"] != "sni.example.com" {
		t.Fatalf("wss.sni = %#v, want sni.example.com", wss["sni"])
	}
}

func TestConvertProxyProviderIntervalToExternalUpdateInterval(t *testing.T) {
	config := map[string]interface{}{
		"proxy-providers": map[string]interface{}{
			"provider-a": map[string]interface{}{
				"url":      "https://example.com/sub",
				"interval": 7200,
			},
		},
		"proxy-groups": []interface{}{
			map[string]interface{}{
				"name": "Auto",
				"type": "url-test",
				"use":  []interface{}{"provider-a"},
			},
		},
	}

	content, _, err := New().Convert(config, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var got map[string]interface{}
	if err := yaml.Unmarshal(content, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	groups := got["policy_groups"].([]interface{})
	external := groups[0].(map[string]interface{})["external"].(map[string]interface{})
	if external["update_interval"] != 7200 {
		t.Fatalf("external.update_interval = %#v, want 7200", external["update_interval"])
	}
}

func TestConvertRuleProviderURLUsesBlackmatrix7SurgeRules(t *testing.T) {
	got, ok := convertRuleProviderURL("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google.yaml")
	if !ok {
		t.Fatal("convertRuleProviderURL() rejected blackmatrix7 Clash rule provider")
	}
	want := "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/Google/Google.list"
	if got != want {
		t.Fatalf("convertRuleProviderURL() = %q, want %q", got, want)
	}
}

func TestConvertSkipsNonBlackmatrix7RuleProvidersWithWarning(t *testing.T) {
	config := map[string]interface{}{
		"rule-providers": map[string]interface{}{
			"Tencent": map[string]interface{}{
				"url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Tencent.yaml",
			},
		},
		"rules": []interface{}{
			"RULE-SET,Tencent,DIRECT",
			"MATCH,Proxy",
		},
	}

	content, warnings, err := New().Convert(config, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %#v, want one warning", warnings)
	}
	if warnings[0] == "" || !containsAll(warnings[0], "Tencent", "blackmatrix7") {
		t.Fatalf("warning = %q, want provider and blackmatrix7 context", warnings[0])
	}
	if string(content) == "" {
		t.Fatal("content is empty")
	}
	var got map[string]interface{}
	if err := yaml.Unmarshal(content, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	rules := got["rules"].([]interface{})
	if len(rules) != 1 {
		t.Fatalf("rules = %#v, want only MATCH/default after skipping rule-set", rules)
	}
	if _, ok := rules[0].(map[string]interface{})["default"]; !ok {
		t.Fatalf("remaining rule = %#v, want default rule", rules[0])
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
