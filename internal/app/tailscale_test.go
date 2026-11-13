package app

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const tailnetConfig = `
proxies:
  - name: Tailnet
    type: tailscale
    hostname: mihomo
    auth-key: tskey-auth-example
    state-dir: ./tailscale
    ephemeral: false
    udp: true
    accept-routes: true
proxy-groups:
  - name: TailnetOnly
    type: select
    proxies: [Tailnet]
rules:
  - DOMAIN-SUFFIX,ts.net,Tailnet
  - IP-CIDR,100.64.0.0/10,Tailnet,no-resolve
  - MATCH,TailnetOnly
`

func TestTailscaleAcrossTargets(t *testing.T) {
	service := NewService()
	for _, target := range []string{"clash", "stash", "singbox", "egern", "loon", "qx"} {
		t.Run(target, func(t *testing.T) {
			result, err := service.ConvertBytes(target, []byte(tailnetConfig))
			if err != nil {
				t.Fatal(err)
			}
			out := string(result.Content)
			if target == "clash" || target == "stash" {
				var doc map[string]interface{}
				if err := yaml.Unmarshal(result.Content, &doc); err != nil {
					t.Fatal(err)
				}
				proxy := doc["proxies"].([]interface{})[0].(map[string]interface{})
				if proxy["type"] != "tailscale" || proxy["auth-key"] != "tskey-auth-example" {
					t.Fatalf("lost Tailscale node: %s", out)
				}
				if target == "stash" && !strings.Contains(strings.Join(result.Warnings, "\n"), "automatically selects an exit node") {
					t.Fatal("missing Stash exit-node behavior warning")
				}
				return
			}
			if target == "singbox" {
				var doc map[string]interface{}
				if err := json.Unmarshal(result.Content, &doc); err != nil {
					t.Fatal(err)
				}
				endpoints, _ := doc["endpoints"].([]interface{})
				if len(endpoints) != 1 {
					t.Fatalf("expected endpoint: %s", out)
				}
				ep := endpoints[0].(map[string]interface{})
				if ep["type"] != "tailscale" || ep["tag"] != "Tailnet" || ep["state_directory"] != "./tailscale" || ep["auth_key"] != "tskey-auth-example" || ep["accept_routes"] != true || ep["ephemeral"] != false {
					t.Fatalf("incorrect endpoint: %#v", ep)
				}
				if len(result.Warnings) != 0 {
					t.Fatalf("unexpected warnings: %v", result.Warnings)
				}
				if !strings.Contains(out, `"outbound": "Tailnet"`) || !strings.Contains(out, `"final": "TailnetOnly"`) {
					t.Fatalf("lost routing: %s", out)
				}
				return
			}
			if !strings.Contains(strings.Join(result.Warnings, "\n"), "using REJECT") {
				t.Fatalf("missing removed-policy warning: %v", result.Warnings)
			}
			switch target {
			case "egern":
				if strings.Contains(out, "policy: Tailnet\n") || !strings.Contains(out, "policy: REJECT") || !strings.Contains(out, "- REJECT") {
					t.Fatalf("dangling rule or direct fallback: %s", out)
				}
			case "loon":
				for _, want := range []string{"TailnetOnly = select,REJECT", "DOMAIN-SUFFIX,ts.net,REJECT", "IP-CIDR,100.64.0.0/10,REJECT,no-resolve"} {
					if !strings.Contains(out, want) {
						t.Fatalf("missing %q: %s", want, out)
					}
				}
			case "qx":
				for _, want := range []string{"static = TailnetOnly, reject", "host-suffix, ts.net, reject", "ip-cidr, 100.64.0.0/10, reject"} {
					if !strings.Contains(out, want) {
						t.Fatalf("missing %q: %s", want, out)
					}
				}
			}
		})
	}
}

func TestRemovedProxyRulesAcrossTargets(t *testing.T) {
	input := strings.ReplaceAll(tailnetConfig, "type: tailscale", "type: unsupported-test-protocol")
	for _, target := range []string{"stash", "singbox", "egern", "loon", "qx"} {
		t.Run(target, func(t *testing.T) {
			result, err := NewService().ConvertBytes(target, []byte(input))
			if err != nil {
				t.Fatal(err)
			}
			out := string(result.Content)
			if !strings.Contains(strings.Join(result.Warnings, "\n"), "using REJECT") {
				t.Fatalf("missing rejection warning: %v", result.Warnings)
			}
			if target == "stash" {
				var doc map[string]interface{}
				if err := yaml.Unmarshal(result.Content, &doc); err != nil {
					t.Fatal(err)
				}
				rules := doc["rules"].([]interface{})
				if rules[0] != "DOMAIN-SUFFIX,ts.net,REJECT" || rules[1] != "IP-CIDR,100.64.0.0/10,REJECT,no-resolve" {
					t.Fatalf("dangling rules: %s", out)
				}
				group := doc["proxy-groups"].([]interface{})[0].(map[string]interface{})
				if group["proxies"].([]interface{})[0] != "REJECT" {
					t.Fatalf("direct fallback: %s", out)
				}
			}
			if target == "singbox" {
				var doc map[string]interface{}
				if err := json.Unmarshal(result.Content, &doc); err != nil {
					t.Fatal(err)
				}
				route := doc["route"].(map[string]interface{})
				if route["final"] != "REJECT" {
					t.Fatalf("direct fallback: %s", out)
				}
			}
		})
	}
}
