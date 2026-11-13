package egern

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTailscaleExportMapping(t *testing.T) {
	input := map[string]interface{}{
		"proxies": []interface{}{map[string]interface{}{
			"name": "ts", "type": "tailscale", "auth-key": "test-auth-key", "hostname": "mihomo",
			"control-url": "https://headscale.example.com", "exit-node": "100.64.0.1",
			"ip-version": "ipv6-prefer", "dialer-proxy": "Bootstrap", "udp": true,
			"state-dir": "./tailscale", "accept-routes": true, "ephemeral": false,
			"exit-node-allow-lan-access": true,
		}},
	}
	data, warnings, err := New().Convert(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	proxy := doc["proxies"].([]interface{})[0].(map[string]interface{})["tailscale"].(map[string]interface{})
	for key, want := range map[string]interface{}{
		"name": "ts", "auth_key": "test-auth-key", "hostname": "mihomo",
		"control_url": "https://headscale.example.com", "exit_node": "100.64.0.1",
		"prefer_ipv6": true, "prev_hop": "Bootstrap", "interactive_login": false,
		"auto_add_magic_dns_rule": false,
	} {
		if proxy[key] != want {
			t.Errorf("%s = %#v, want %#v", key, proxy[key], want)
		}
	}
	for _, key := range []string{"server", "port", "ip_version", "state", "state_dir", "accept_routes", "ephemeral", "derp_only", "accept_incoming", "advertise_exit_node"} {
		if _, ok := proxy[key]; ok {
			t.Errorf("unverified field %q emitted", key)
		}
	}
	for _, field := range []string{"state-dir", "accept-routes", "ephemeral", "exit-node-allow-lan-access"} {
		if !strings.Contains(strings.Join(warnings, "\n"), field) {
			t.Errorf("missing warning for %s: %v", field, warnings)
		}
	}
	if input["proxies"].([]interface{})[0].(map[string]interface{})["state-dir"] != "./tailscale" {
		t.Fatal("mutated input")
	}
}

func TestTailscaleInteractiveLoginAndUnsupportedExit(t *testing.T) {
	for _, tc := range []struct {
		name, auth  string
		interactive bool
	}{
		{"without key", "", true}, {"with key", "test-key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var warnings []string
			entry := convertTailscaleToEgern(map[string]interface{}{"name": "ts", "auth-key": tc.auth, "udp": true}, &warnings)
			proxy := entry["tailscale"].(map[string]interface{})
			if proxy["interactive_login"] != tc.interactive || len(warnings) != 0 {
				t.Fatalf("node %#v; warnings %v", proxy, warnings)
			}
		})
	}
	config := map[string]interface{}{
		"proxies": []interface{}{map[string]interface{}{"name": "ts", "type": "tailscale", "exit-node": "auto:any"}},
		"rules":   []interface{}{"DOMAIN-SUFFIX,ts.net,ts", "MATCH,ts"},
	}
	data, warnings, err := New().Convert(config, nil)
	if err != nil || strings.Contains(string(data), "policy: ts") || !strings.Contains(string(data), "policy: REJECT") || !strings.Contains(strings.Join(warnings, "\n"), "auto:any") {
		t.Fatalf("err %v; warnings %v; output %s", err, warnings, data)
	}
}
