package qx

import (
	"strings"
	"testing"
)

// buildProxies is a helper to create a proxy map slice for tests.
func buildProxies(entries ...map[string]interface{}) []map[string]interface{} {
	return entries
}

// buildGroups is a helper to create a group map slice for tests.
func buildGroups(entries ...map[string]interface{}) []map[string]interface{} {
	return entries
}

func TestBuildChainInfo_TransitiveDetection(t *testing.T) {
	// Proxy "jp-ss" uses dialer-proxy "Transit".
	// Group "ProxyChain" contains "jp-ss" (chain) and "us-ss" (not chain) — mixed.
	// Group "Choose" contains "ProxyChain" — transitively chain-capable.
	proxies := buildProxies(
		map[string]interface{}{"name": "jp-ss", "type": "ss", "server": "jp.example.com", "dialer-proxy": "Transit"},
		map[string]interface{}{"name": "us-ss", "type": "ss", "server": "us.example.com"},
	)
	groups := buildGroups(
		map[string]interface{}{"name": "Transit", "type": "select", "proxies": []interface{}{"us-ss"}},
		map[string]interface{}{"name": "ProxyChain", "type": "select", "proxies": []interface{}{"jp-ss", "us-ss"}},
		map[string]interface{}{"name": "Choose", "type": "select", "proxies": []interface{}{"ProxyChain", "direct"}},
		map[string]interface{}{"name": "Unrelated", "type": "select", "proxies": []interface{}{"us-ss", "direct"}},
	)

	chainProxies, chainCapable := buildChainInfo(proxies, groups)

	if _, ok := chainProxies["jp-ss"]; !ok {
		t.Error("jp-ss should be in chainProxies")
	}
	if !chainCapable["ProxyChain"] {
		t.Error("ProxyChain should be chain-capable (contains jp-ss which has dialer-proxy)")
	}
	if !chainCapable["Choose"] {
		t.Error("Choose should be transitively chain-capable (contains ProxyChain)")
	}
	if chainCapable["Unrelated"] {
		t.Error("Unrelated should NOT be chain-capable")
	}
	if chainCapable["Transit"] {
		t.Error("Transit should NOT be chain-capable (it is the transit target, not a chain consumer)")
	}
}

func TestConvertFilters_ViaInterfaceOnChainCapable(t *testing.T) {
	proxies := buildProxies(
		map[string]interface{}{"name": "jp-ss", "type": "ss", "server": "jp.example.com", "dialer-proxy": "Transit"},
		map[string]interface{}{"name": "us-ss", "type": "ss", "server": "us.example.com"},
	)
	groups := buildGroups(
		map[string]interface{}{"name": "Transit", "type": "select", "proxies": []interface{}{"us-ss"}},
		map[string]interface{}{"name": "ProxyChain", "type": "select", "proxies": []interface{}{"jp-ss", "us-ss"}},
		map[string]interface{}{"name": "Choose", "type": "select", "proxies": []interface{}{"ProxyChain", "direct"}},
	)
	_, chainCapable := buildChainInfo(proxies, groups)

	rules := []interface{}{
		"DOMAIN-SUFFIX,example.com,Choose",
		"MATCH,Choose",
	}

	localText, _, _ := convertFilters(rules, nil, proxies, chainCapable)

	if !strings.Contains(localText, "via-interface=%TUN%") {
		t.Errorf("expected via-interface=%%TUN%% in filter_local, got:\n%s", localText)
	}
	// Verify chain server route is present
	if !strings.Contains(localText, "host-suffix, jp.example.com, Transit") {
		t.Errorf("expected chain server route for jp.example.com, got:\n%s", localText)
	}
}

func TestConvertDNS_MultipleDoHOnOneLine(t *testing.T) {
	cfg := map[string]interface{}{
		"dns": map[string]interface{}{
			"enable": true,
			"nameserver": []interface{}{
				"https://dns.google/dns-query",
				"https://1.1.1.1/dns-query",
				"8.8.8.8",
			},
		},
	}
	got := convertDNS(cfg)
	if strings.Count(got, "doh-server") > 1 {
		t.Errorf("expected a single doh-server line, got:\n%s", got)
	}
	if !strings.Contains(got, "doh-server = https://dns.google/dns-query,https://1.1.1.1/dns-query") {
		t.Errorf("expected both DoH servers joined on one line, got:\n%s", got)
	}
}

func TestConvertFilters_NoViaInterfaceWithoutChain(t *testing.T) {
	proxies := buildProxies(
		map[string]interface{}{"name": "us-ss", "type": "ss", "server": "us.example.com"},
	)
	groups := buildGroups(
		map[string]interface{}{"name": "Proxy", "type": "select", "proxies": []interface{}{"us-ss", "direct"}},
	)
	_, chainCapable := buildChainInfo(proxies, groups)

	rules := []interface{}{
		"DOMAIN-SUFFIX,example.com,Proxy",
		"MATCH,Proxy",
	}

	localText, _, _ := convertFilters(rules, nil, proxies, chainCapable)

	if strings.Contains(localText, "via-interface=%TUN%") {
		t.Errorf("did not expect via-interface=%%TUN%% when no chain proxies, got:\n%s", localText)
	}
}
