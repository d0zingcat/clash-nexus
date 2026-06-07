package qx

import (
	"errors"
	"net"
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
	// Group "Choose" contains "ProxyChain", so it transitively affects chain routing.
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

	chainProxies, proxyChainGroups := buildChainInfo(proxies, groups)
	chainAffecting := buildChainAffectingPolicies(groups, proxyChainGroups)

	if _, ok := chainProxies["jp-ss"]; !ok {
		t.Error("jp-ss should be in chainProxies")
	}
	if !proxyChainGroups["ProxyChain"] {
		t.Error("ProxyChain should be a proxy-chain group (contains jp-ss which has dialer-proxy)")
	}
	if proxyChainGroups["Choose"] {
		t.Error("Choose should NOT be a direct proxy-chain group")
	}
	if !chainAffecting["ProxyChain"] {
		t.Error("ProxyChain should affect chain routing")
	}
	if !chainAffecting["Choose"] {
		t.Error("Choose should transitively affect chain routing via ProxyChain")
	}
	if chainAffecting["Unrelated"] {
		t.Error("Unrelated should NOT affect chain routing")
	}
	if chainAffecting["Transit"] {
		t.Error("Transit should NOT affect chain routing (it is the transit target, not a chain consumer)")
	}
}

func TestConvertFilters_ViaInterfaceOnlyOnProxyChainGroup(t *testing.T) {
	oldResolve := resolveHostIPs
	resolveHostIPs = func(host string) ([]net.IP, error) {
		if host != "jp.example.com" {
			return nil, errors.New("unexpected host")
		}
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	}
	defer func() { resolveHostIPs = oldResolve }()

	proxies := buildProxies(
		map[string]interface{}{"name": "jp-ss", "type": "ss", "server": "jp.example.com", "dialer-proxy": "Transit"},
		map[string]interface{}{"name": "us-ss", "type": "ss", "server": "us.example.com"},
	)
	groups := buildGroups(
		map[string]interface{}{"name": "Transit", "type": "select", "proxies": []interface{}{"us-ss"}},
		map[string]interface{}{"name": "ProxyChain", "type": "select", "proxies": []interface{}{"jp-ss", "us-ss"}},
		map[string]interface{}{"name": "Choose", "type": "select", "proxies": []interface{}{"ProxyChain", "direct"}},
	)
	_, proxyChainGroups := buildChainInfo(proxies, groups)
	chainAffecting := buildChainAffectingPolicies(groups, proxyChainGroups)

	rules := []interface{}{
		"DOMAIN-SUFFIX,chain.example.com,ProxyChain",
		"DOMAIN-SUFFIX,regular.example.com,Choose",
		"DOMAIN-SUFFIX,proxy.example.com,jp-ss",
		"MATCH,Choose",
	}

	localText, _, _ := convertFilters(rules, nil, proxies, chainAffecting)

	if !strings.Contains(localText, "host-suffix, chain.example.com, ProxyChain, via-interface=%TUN%") {
		t.Errorf("expected via-interface=%%TUN%% for ProxyChain rule, got:\n%s", localText)
	}
	if !strings.Contains(localText, "host-suffix, regular.example.com, Choose, via-interface=%TUN%") {
		t.Errorf("expected via-interface=%%TUN%% for Choose rule that can select ProxyChain, got:\n%s", localText)
	}
	if strings.Contains(localText, "host-suffix, proxy.example.com, jp-ss, via-interface=%TUN%") {
		t.Errorf("did not expect via-interface=%%TUN%% when rule policy is a proxy node, got:\n%s", localText)
	}
	if !strings.Contains(localText, "final, Choose, via-interface=%TUN%") {
		t.Errorf("expected via-interface=%%TUN%% for MATCH policy that can select ProxyChain, got:\n%s", localText)
	}
	// Verify chain server route is present
	if !strings.Contains(localText, "ip-cidr, 203.0.113.10/32, Transit") {
		t.Errorf("expected chain server IP route for jp.example.com, got:\n%s", localText)
	}
}

func TestChainServerIPRoutes_ResolvesDomainsAndKeepsLiteralIPs(t *testing.T) {
	oldResolve := resolveHostIPs
	resolveHostIPs = func(host string) ([]net.IP, error) {
		if host != "jp.example.com" {
			return nil, errors.New("unexpected host")
		}
		return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("2001:db8::10")}, nil
	}
	defer func() { resolveHostIPs = oldResolve }()

	proxies := buildProxies(
		map[string]interface{}{"name": "jp-ss", "type": "ss", "server": "jp.example.com", "dialer-proxy": "Transit"},
		map[string]interface{}{"name": "literal-ss", "type": "ss", "server": "198.51.100.7", "dialer-proxy": "Transit"},
	)

	routes, warnings := chainServerIPRoutes(proxies)
	got := strings.Join(routes, "\n")

	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %#v", warnings)
	}
	if !strings.Contains(got, "ip-cidr, 203.0.113.10/32, Transit") {
		t.Errorf("expected resolved IPv4 route, got:\n%s", got)
	}
	if !strings.Contains(got, "ip6-cidr, 2001:db8::10/128, Transit") {
		t.Errorf("expected resolved IPv6 route, got:\n%s", got)
	}
	if !strings.Contains(got, "ip-cidr, 198.51.100.7/32, Transit") {
		t.Errorf("expected literal IP route, got:\n%s", got)
	}
}

func TestChainServerIPRoutes_WarnsOnResolveFailure(t *testing.T) {
	oldResolve := resolveHostIPs
	resolveHostIPs = func(host string) ([]net.IP, error) {
		return nil, errors.New("lookup failed")
	}
	defer func() { resolveHostIPs = oldResolve }()

	proxies := buildProxies(
		map[string]interface{}{"name": "jp-ss", "type": "ss", "server": "jp.example.com", "dialer-proxy": "Transit"},
	)

	routes, warnings := chainServerIPRoutes(proxies)

	if len(routes) != 0 {
		t.Fatalf("expected no routes on resolve failure, got: %#v", routes)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "cannot resolve dialer-proxy server") {
		t.Fatalf("expected resolve warning, got: %#v", warnings)
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
	_, proxyChainGroups := buildChainInfo(proxies, groups)
	chainAffecting := buildChainAffectingPolicies(groups, proxyChainGroups)

	rules := []interface{}{
		"DOMAIN-SUFFIX,example.com,Proxy",
		"MATCH,Proxy",
	}

	localText, _, _ := convertFilters(rules, nil, proxies, chainAffecting)

	if strings.Contains(localText, "via-interface=%TUN%") {
		t.Errorf("did not expect via-interface=%%TUN%% when no chain proxies, got:\n%s", localText)
	}
}
