package stash

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"clash-nexus/converter"
)

func TestConverterMetadataAndEmptyConfig(t *testing.T) {
	var _ converter.Converter = New()

	c := New()
	if got := c.Name(); got != "stash" {
		t.Errorf("Name() = %q, want %q", got, "stash")
	}
	if got := c.DefaultExtension(); got != ".yaml" {
		t.Errorf("DefaultExtension() = %q, want %q", got, ".yaml")
	}

	output, warnings, err := c.Convert(map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("Convert() warnings = %v, want none", warnings)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(output, &config); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	if len(config) != 0 {
		t.Errorf("converted config = %v, want empty map", config)
	}
}

func TestConvertStripsRuntimeAndUnsupportedDNSFields(t *testing.T) {
	input := map[string]interface{}{
		"mode":            "rule",
		"log-level":       "info",
		"hosts":           map[string]interface{}{"example.com": "1.2.3.4"},
		"proxies":         []interface{}{map[string]interface{}{"name": "proxy"}},
		"proxy-groups":    []interface{}{map[string]interface{}{"name": "group"}},
		"proxy-providers": map[string]interface{}{"provider": map[string]interface{}{}},
		"rule-providers":  map[string]interface{}{"provider": map[string]interface{}{}},
		"rules":           []interface{}{"MATCH,DIRECT"},
		"mixed-port":      7890,
		"tun": map[string]interface{}{
			"enable": true,
		},
		"sniffer": map[string]interface{}{
			"enable": true,
		},
		"dns": map[string]interface{}{
			"default-nameserver": []interface{}{"223.5.5.5"},
			"nameserver":         []interface{}{"1.1.1.1"},
			"nameserver-policy":  map[string]interface{}{"example.com": []interface{}{"8.8.8.8"}},
			"fake-ip-filter":     []interface{}{"*.lan"},
			"skip-cert-verify":   true,
			"follow-rule":        true,
			"fallback":           []interface{}{"8.8.8.8"},
			"listen":             "0.0.0.0:1053",
		},
	}

	output, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(output, &config); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	if got := config["mode"]; got != "rule" {
		t.Errorf("mode = %v, want rule", got)
	}
	for _, field := range []string{
		"log-level", "hosts", "proxies", "proxy-groups", "proxy-providers",
		"rule-providers", "rules",
	} {
		if _, exists := config[field]; !exists {
			t.Errorf("top-level field %q must be retained", field)
		}
	}
	for _, field := range []string{"mixed-port", "tun", "sniffer"} {
		if _, exists := config[field]; exists {
			t.Errorf("top-level field %q must be removed, got %v", field, config[field])
		}
	}

	dns, ok := config["dns"].(map[string]interface{})
	if !ok {
		t.Fatalf("dns = %T %v, want map", config["dns"], config["dns"])
	}
	for _, field := range []string{
		"default-nameserver", "nameserver", "nameserver-policy", "fake-ip-filter",
		"skip-cert-verify", "follow-rule",
	} {
		if _, exists := dns[field]; !exists {
			t.Errorf("dns field %q must be retained", field)
		}
	}
	for _, field := range []string{"fallback", "listen"} {
		if _, exists := dns[field]; exists {
			t.Errorf("dns field %q must be removed, got %v", field, dns[field])
		}
	}

	for _, field := range []string{"mixed-port", "tun", "sniffer", "fallback", "listen"} {
		if !containsWarningForField(warnings, field) {
			t.Errorf("warnings = %v, want warning for %q", warnings, field)
		}
	}

	if got := input["mixed-port"]; got != 7890 {
		t.Errorf("input mixed-port = %v, want 7890", got)
	}
	inputDNS := input["dns"].(map[string]interface{})
	if got := inputDNS["fallback"]; !equalStringSlice(got, []interface{}{"8.8.8.8"}) {
		t.Errorf("input dns fallback = %v, want [8.8.8.8]", got)
	}
	if got := inputDNS["listen"]; got != "0.0.0.0:1053" {
		t.Errorf("input dns listen = %v, want 0.0.0.0:1053", got)
	}
}

func TestConvertDropsNonMappingDNS(t *testing.T) {
	output, warnings, err := New().Convert(map[string]interface{}{"dns": "invalid"}, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(output, &config); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	if _, exists := config["dns"]; exists {
		t.Errorf("dns must be omitted for a non-mapping value, got %v", config["dns"])
	}
	if !containsWarningForField(warnings, "dns") {
		t.Errorf("warnings = %v, want warning for dns", warnings)
	}
}

func TestConvertWarningsAreDeterministicAndSorted(t *testing.T) {
	input := map[string]interface{}{
		"z-runtime": true,
		"a-runtime": true,
		"dns": map[string]interface{}{
			"z-dns": true,
			"a-dns": true,
		},
		"tun": true,
	}

	_, firstWarnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("first Convert() error = %v", err)
	}
	_, secondWarnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("second Convert() error = %v", err)
	}

	if !reflect.DeepEqual(firstWarnings, secondWarnings) {
		t.Errorf("warnings differ between conversions: first %v, second %v", firstWarnings, secondWarnings)
	}

	want := []string{
		`removed unsupported top-level field "a-runtime"`,
		`removed unsupported dns field "a-dns"`,
		`removed unsupported dns field "z-dns"`,
		`removed unsupported top-level field "tun"`,
		`removed unsupported top-level field "z-runtime"`,
	}
	if !reflect.DeepEqual(firstWarnings, want) {
		t.Errorf("warnings = %v, want %v", firstWarnings, want)
	}
}

func TestConvertWarningsAreSorted(t *testing.T) {
	input := map[string]interface{}{
		"z-top":   true,
		"a-top":   true,
		"dns":     map[string]interface{}{"z-dns": true, "a-dns": true},
		"mode":    "rule",
		"sniffer": map[string]interface{}{"enable": true},
	}

	_, firstWarnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("first Convert() error = %v", err)
	}
	_, secondWarnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("second Convert() error = %v", err)
	}
	if strings.Join(firstWarnings, "\n") != strings.Join(secondWarnings, "\n") {
		t.Fatalf("warning order is unstable: first=%v second=%v", firstWarnings, secondWarnings)
	}
	wantWarnings := []string{
		`removed unsupported top-level field "a-top"`,
		`removed unsupported dns field "a-dns"`,
		`removed unsupported dns field "z-dns"`,
		`removed unsupported top-level field "sniffer"`,
		`removed unsupported top-level field "z-top"`,
	}
	if strings.Join(firstWarnings, "\n") != strings.Join(wantWarnings, "\n") {
		t.Fatalf("warnings = %v, want %v", firstWarnings, wantWarnings)
	}
}

func TestConvertRebuildsProxiesUsingStashFieldWhitelist(t *testing.T) {
	input := map[string]interface{}{
		"proxies": []interface{}{
			map[string]interface{}{
				"name":                       "tailnet",
				"type":                       "tailscale",
				"auth-key":                   "tskey-auth-example",
				"hostname":                   "stash-phone",
				"control-url":                "https://headscale.example.com",
				"ephemeral":                  true,
				"exit-node":                  "exit.example.ts.net",
				"state-dir":                  "/var/lib/tailscale",
				"accept-routes":              true,
				"exit-node-allow-lan-access": true,
				"routing-mark":               42,
				"ip-version":                 "dual",
			},
			map[string]interface{}{
				"name":   "legacy",
				"type":   "mieru",
				"server": "legacy.example.com",
				"port":   443,
			},
			map[string]interface{}{
				"name":         "ss-main",
				"type":         "ss",
				"server":       "ss.example.com",
				"port":         443,
				"cipher":       "aes-256-gcm",
				"password":     "secret",
				"udp":          true,
				"plugin":       "v2ray-plugin",
				"plugin-opts":  map[string]interface{}{"mode": "websocket"},
				"dialer-proxy": "bootstrap",
				"smux":         map[string]interface{}{"enabled": true},
			},
			map[string]interface{}{
				"name":   "missing-ss-password",
				"type":   "ss",
				"server": "ss.example.com",
				"port":   443,
				"cipher": "aes-256-gcm",
			},
			"not a mapping",
			map[string]interface{}{"name": "missing-type"},
			map[string]interface{}{"type": "ss"},
		},
	}

	output, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(output, &config); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	proxies, ok := config["proxies"].([]interface{})
	if !ok {
		t.Fatalf("proxies = %T %v, want sequence", config["proxies"], config["proxies"])
	}
	if len(proxies) != 2 {
		t.Fatalf("proxies = %v, want only the two supported valid nodes", proxies)
	}

	tailnet, ok := proxies[0].(map[string]interface{})
	if !ok {
		t.Fatalf("tailnet proxy = %T %v, want mapping", proxies[0], proxies[0])
	}
	for _, field := range []string{"name", "type", "auth-key", "hostname", "control-url", "ephemeral", "exit-node"} {
		if _, exists := tailnet[field]; !exists {
			t.Errorf("tailscale field %q must be retained", field)
		}
	}
	for _, field := range []string{"state-dir", "accept-routes", "exit-node-allow-lan-access", "routing-mark", "ip-version"} {
		if _, exists := tailnet[field]; exists {
			t.Errorf("tailscale field %q must be removed, got %v", field, tailnet[field])
		}
		if !containsWarningForField(warnings, field) {
			t.Errorf("warnings = %v, want warning for %q", warnings, field)
		}
	}

	ss, ok := proxies[1].(map[string]interface{})
	if !ok {
		t.Fatalf("ss proxy = %T %v, want mapping", proxies[1], proxies[1])
	}
	for _, field := range []string{"name", "type", "server", "port", "cipher", "password", "udp", "plugin", "plugin-opts", "dialer-proxy"} {
		if _, exists := ss[field]; !exists {
			t.Errorf("ss field %q must be retained", field)
		}
	}
	if _, exists := ss["smux"]; exists {
		t.Errorf("ss smux must be removed, got %v", ss["smux"])
	}
	if !containsWarningForField(warnings, "smux") {
		t.Errorf("warnings = %v, want warning for smux", warnings)
	}
	if !containsWarningForField(warnings, "legacy") || !containsWarningForField(warnings, "mieru") {
		t.Errorf("warnings = %v, want warning naming unsupported legacy mieru proxy", warnings)
	}
	if !containsWarningForField(warnings, "missing-ss-password") || !containsWarningForField(warnings, "password") {
		t.Errorf("warnings = %v, want warning naming incomplete SS proxy and missing password", warnings)
	}
	for _, warning := range []string{"expected mapping", "missing-type"} {
		if !containsWarningForField(warnings, warning) {
			t.Errorf("warnings = %v, want warning for %q", warnings, warning)
		}
	}

	inputProxies := input["proxies"].([]interface{})
	inputTailscale := inputProxies[0].(map[string]interface{})
	for _, field := range []string{"state-dir", "accept-routes", "exit-node-allow-lan-access", "routing-mark", "ip-version"} {
		if _, exists := inputTailscale[field]; !exists {
			t.Errorf("input tailscale field %q must remain unchanged", field)
		}
	}
	if _, exists := inputProxies[2].(map[string]interface{})["smux"]; !exists {
		t.Error("input ss smux must remain unchanged")
	}
}

func TestConvertRetainsVMessServername(t *testing.T) {
	input := map[string]interface{}{
		"proxies": []interface{}{
			map[string]interface{}{
				"name":       "vmess-with-servername",
				"type":       "vmess",
				"server":     "edge.example.com",
				"servername": "origin.example.com",
				"port":       443,
				"uuid":       "00000000-0000-0000-0000-000000000000",
				"tls":        true,
			},
		},
	}

	output, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(output, &config); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	proxies := config["proxies"].([]interface{})
	vmess := proxies[0].(map[string]interface{})
	if got := vmess["servername"]; got != "origin.example.com" {
		t.Errorf("VMess servername = %v, want origin.example.com", got)
	}
	if containsWarningForField(warnings, "servername") {
		t.Errorf("warnings = %v, must not remove VMess servername", warnings)
	}
}

func TestConvertRebuildsGroupsProvidersAndRules(t *testing.T) {
	input := map[string]interface{}{
		"proxy-groups": []interface{}{
			map[string]interface{}{
				"name":              "auto",
				"type":              "url-test",
				"proxies":           []interface{}{"a", "b"},
				"use":               []interface{}{"provider"},
				"filter":            "HK",
				"include-all":       true,
				"url":               "https://example.com/test",
				"interval":          300,
				"lazy":              true,
				"strategy":          "consistent-hashing",
				"tolerance":         50,
				"ssid-policy":       map[string]interface{}{"home": "DIRECT"},
				"icon":              "https://example.com/icon.png",
				"benchmark-url":     "https://example.com/benchmark",
				"benchmark-timeout": 5000,
				"hidden":            true,
			},
			"not a group",
		},
		"proxy-providers": map[string]interface{}{
			"remote": map[string]interface{}{
				"url":            "https://example.com/proxies.yaml",
				"path":           "./proxies.yaml",
				"interval":       3600,
				"headers":        map[string]interface{}{"Authorization": "Bearer token"},
				"filter":         "HK",
				"exclude-filter": "US",
				"health-check":   map[string]interface{}{"enable": true},
				"type":           "http",
			},
			"invalid": "not a provider",
		},
		"rule-providers": map[string]interface{}{
			"ads": map[string]interface{}{
				"url":      "https://example.com/ads.yaml",
				"path":     "./ads.yaml",
				"interval": 86400,
				"behavior": "domain",
				"format":   "yaml",
				"type":     "http",
			},
		},
		"rules": []interface{}{
			"DOMAIN,example.com,DIRECT",
			"DOMAIN-SUFFIX,example.org,DIRECT",
			"MATCH,DIRECT",
			"PROCESS-NAME,Example,DIRECT",
			"IN-PORT,80,DIRECT",
			"UID,1000,DIRECT",
			"DSCP,46,DIRECT",
			"SUB-RULE,child",
			"UNKNOWN,value,DIRECT",
			"",
			42,
		},
	}
	original := cloneConfig(input)

	output, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if !reflect.DeepEqual(input, original) {
		t.Errorf("Convert() modified input: got %v, want %v", input, original)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(output, &config); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	groups := config["proxy-groups"].([]interface{})
	if len(groups) != 1 {
		t.Fatalf("proxy-groups = %v, want one valid group", groups)
	}
	group := groups[0].(map[string]interface{})
	for _, field := range []string{
		"name", "type", "proxies", "use", "filter", "include-all", "url", "interval",
		"lazy", "strategy", "tolerance", "ssid-policy", "icon", "benchmark-url", "benchmark-timeout",
	} {
		if _, exists := group[field]; !exists {
			t.Errorf("group field %q must be retained", field)
		}
	}
	if _, exists := group["hidden"]; exists {
		t.Errorf("group field hidden must be removed, got %v", group["hidden"])
	}

	proxyProviders := config["proxy-providers"].(map[string]interface{})
	remote := proxyProviders["remote"].(map[string]interface{})
	for _, field := range []string{"url", "path", "interval", "headers", "filter", "exclude-filter", "health-check"} {
		if _, exists := remote[field]; !exists {
			t.Errorf("proxy provider field %q must be retained", field)
		}
	}
	if _, exists := remote["type"]; exists {
		t.Errorf("proxy provider type must be removed, got %v", remote["type"])
	}
	if _, exists := proxyProviders["invalid"]; exists {
		t.Errorf("non-mapping proxy provider must be removed, got %v", proxyProviders["invalid"])
	}

	ruleProviders := config["rule-providers"].(map[string]interface{})
	ads := ruleProviders["ads"].(map[string]interface{})
	for _, field := range []string{"url", "path", "interval", "behavior", "format"} {
		if _, exists := ads[field]; !exists {
			t.Errorf("rule provider field %q must be retained", field)
		}
	}
	if _, exists := ads["type"]; exists {
		t.Errorf("rule provider type must be removed, got %v", ads["type"])
	}

	rules := config["rules"].([]interface{})
	wantRules := []interface{}{
		"DOMAIN,example.com,DIRECT",
		"DOMAIN-SUFFIX,example.org,DIRECT",
		"MATCH,DIRECT",
		"PROCESS-NAME,Example,DIRECT",
	}
	if !reflect.DeepEqual(rules, wantRules) {
		t.Errorf("rules = %v, want %v", rules, wantRules)
	}

	for _, field := range []string{
		"hidden", "expected mapping", "type", "invalid", "PROCESS-NAME,Example,DIRECT",
		"iOS/tvOS", "IN-PORT", "UID", "DSCP", "SUB-RULE", "UNKNOWN", "empty rule", "expected string",
	} {
		if !containsWarningForField(warnings, field) {
			t.Errorf("warnings = %v, want warning for %q", warnings, field)
		}
	}
}

func TestConvertDropsIncompleteRules(t *testing.T) {
	input := map[string]interface{}{
		"rules": []interface{}{
			"DOMAIN",
			"DOMAIN,,DIRECT",
			"MATCH,",
			"SCRIPT,,DIRECT",
			"MATCH,DIRECT",
			"DOMAIN-SUFFIX,example.org,DIRECT",
		},
	}

	output, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(output, &config); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	wantRules := []interface{}{
		"MATCH,DIRECT",
		"DOMAIN-SUFFIX,example.org,DIRECT",
	}
	if got := config["rules"]; !reflect.DeepEqual(got, wantRules) {
		t.Errorf("rules = %v, want %v", got, wantRules)
	}

	for _, rule := range []string{"DOMAIN", "DOMAIN,,DIRECT", "MATCH,", "SCRIPT,,DIRECT"} {
		if !containsWarningForField(warnings, rule) || !containsWarningForField(warnings, "incomplete") {
			t.Errorf("warnings = %v, want incomplete-rule warning for %q", warnings, rule)
		}
	}
}

func TestConvertValidatesRulesBeforeTrailingModifiers(t *testing.T) {
	input := map[string]interface{}{
		"rules": []interface{}{
			"GEOIP,CN,no-resolve",
			"MATCH,,DIRECT",
			"SCRIPT,,DIRECT,no-resolve",
			"GEOIP,CN,DIRECT,no-resolve",
			"MATCH,DIRECT",
			"SCRIPT,shortcut,DIRECT,no-track",
		},
	}

	output, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(output, &config); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	wantRules := []interface{}{
		"GEOIP,CN,DIRECT,no-resolve",
		"MATCH,DIRECT",
		"SCRIPT,shortcut,DIRECT,no-track",
	}
	if got := config["rules"]; !reflect.DeepEqual(got, wantRules) {
		t.Errorf("rules = %v, want %v", got, wantRules)
	}

	for _, rule := range []string{"GEOIP,CN,no-resolve", "MATCH,,DIRECT", "SCRIPT,,DIRECT,no-resolve"} {
		if !containsWarningForField(warnings, rule) || !containsWarningForField(warnings, "incomplete") {
			t.Errorf("warnings = %v, want incomplete-rule warning for %q", warnings, rule)
		}
	}
}

func TestConvertStrictlyValidatesRuleModifiersAndFields(t *testing.T) {
	input := map[string]interface{}{
		"rules": []interface{}{
			"DOMAIN,example.com,DIRECT,invalid",
			"DOMAIN,example.com,no-resolve,DIRECT",
			"MATCH,DIRECT,no-resolve",
			"AND,((DOMAIN,example.com,DIRECT),(DOMAIN-SUFFIX,example.org,DIRECT)),DIRECT",
			"DOMAIN,example.com,DIRECT,no-resolve",
		},
	}

	output, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(output, &config); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	wantRules := []interface{}{
		"AND,((DOMAIN,example.com,DIRECT),(DOMAIN-SUFFIX,example.org,DIRECT)),DIRECT",
		"DOMAIN,example.com,DIRECT,no-resolve",
	}
	if got := config["rules"]; !reflect.DeepEqual(got, wantRules) {
		t.Errorf("rules = %v, want %v", got, wantRules)
	}

	for _, rule := range []string{
		"DOMAIN,example.com,DIRECT,invalid",
		"DOMAIN,example.com,no-resolve,DIRECT",
		"MATCH,DIRECT,no-resolve",
	} {
		if !containsWarningForField(warnings, rule) || !containsWarningForField(warnings, "invalid") {
			t.Errorf("warnings = %v, want invalid-rule warning for %q", warnings, rule)
		}
	}
}

func cloneConfig(config map[string]interface{}) map[string]interface{} {
	var clone map[string]interface{}
	content, err := yaml.Marshal(config)
	if err != nil {
		panic(err)
	}
	if err := yaml.Unmarshal(content, &clone); err != nil {
		panic(err)
	}
	return clone
}

func equalStringSlice(got interface{}, want []interface{}) bool {
	gotSlice, ok := got.([]interface{})
	if !ok || len(gotSlice) != len(want) {
		return false
	}
	for i := range want {
		if gotSlice[i] != want[i] {
			return false
		}
	}
	return true
}

func containsWarningForField(warnings []string, field string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, field) {
			return true
		}
	}
	return false
}
