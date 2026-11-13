package singbox

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTailscaleEndpointOptionsAndDetour(t *testing.T) {
	input := `proxies:
  - {name: Bootstrap, type: direct}
  - name: Tailnet
    type: tailscale
    control-url: https://headscale.example.com
    hostname: test
    ephemeral: true
    accept-routes: false
    exit-node: 100.64.0.1
    exit-node-allow-lan-access: true
    dialer-proxy: Bootstrap
    interface-name: en0
    routing-mark: 42
    udp: true
rules: ["MATCH,Tailnet"]
`
	var config map[string]interface{}
	if err := yaml.Unmarshal([]byte(input), &config); err != nil {
		t.Fatal(err)
	}
	data, warnings, err := New().Convert(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	ep := endpointsByTag(decodeJSON(t, data))["Tailnet"]
	for key, want := range map[string]interface{}{
		"control_url": "https://headscale.example.com", "hostname": "test", "ephemeral": true,
		"accept_routes": false, "exit_node": "100.64.0.1", "exit_node_allow_lan_access": true,
		"detour": "Bootstrap", "bind_interface": "en0", "routing_mark": float64(42),
	} {
		if ep[key] != want {
			t.Errorf("%s = %#v, want %#v", key, ep[key], want)
		}
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
}

func TestUnrepresentableTailscaleSelectorRejectsRules(t *testing.T) {
	config := map[string]interface{}{
		"proxies": []interface{}{map[string]interface{}{"name": "Tailnet", "type": "tailscale", "exit-node": "auto:any"}},
		"rules":   []interface{}{"DOMAIN-SUFFIX,ts.net,Tailnet", "MATCH,Tailnet"},
	}
	data, warnings, err := New().Convert(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := decodeJSON(t, data)
	if len(endpointsByTag(out)) != 0 || out["route"].(map[string]interface{})["final"] != "REJECT" {
		t.Fatalf("unexpected output: %s", data)
	}
	rule := out["route"].(map[string]interface{})["rules"].([]interface{})[0].(map[string]interface{})
	if rule["outbound"] != "REJECT" || !strings.Contains(strings.Join(warnings, "\n"), "auto:any") {
		t.Fatalf("rule: %#v, warnings: %v", rule, warnings)
	}
}

func TestTailscaleUDPToggleWarning(t *testing.T) {
	for _, udp := range []interface{}{nil, false} {
		proxy := map[string]interface{}{"name": "Tailnet", "type": "tailscale"}
		if udp != nil {
			proxy["udp"] = udp
		}
		_, warnings, err := New().Convert(map[string]interface{}{"proxies": []interface{}{proxy}}, nil)
		if err != nil || !strings.Contains(strings.Join(warnings, "\n"), "disabling UDP") {
			t.Fatalf("err: %v, warnings: %v", err, warnings)
		}
	}
}
