package singbox

import (
	"strings"

	"clash-nexus/converter/clash"
)

// Tailscale is an endpoint in sing-box 1.12+, without a server or port.
func (b *builder) buildTailscaleEndpoint(proxy map[string]interface{}) map[string]interface{} {
	name := strings.TrimSpace(clash.MapGetStr(proxy, "name", ""))
	if name == "" {
		b.warnf("skipping Tailscale proxy: missing name")
		return nil
	}
	out := map[string]interface{}{"type": "tailscale", "tag": name}
	fields := map[string]string{
		"auth-key": "auth_key", "hostname": "hostname", "control-url": "control_url",
		"state-dir": "state_directory", "ephemeral": "ephemeral",
		"accept-routes": "accept_routes", "exit-node": "exit_node",
		"exit-node-allow-lan-access": "exit_node_allow_lan_access",
		"dialer-proxy":               "detour", "interface-name": "bind_interface", "routing-mark": "routing_mark",
	}
	for _, key := range sortedKeys(proxy) {
		if field, ok := fields[key]; ok {
			if key == "exit-node" && strings.TrimSpace(clash.MapGetStr(proxy, key, "")) == "auto:any" {
				b.warnf("skipping Tailscale proxy %q: sing-box does not document the auto:any exit-node selector; use an explicit exit node", name)
				return nil
			}
			out[field] = proxy[key]
		} else if key != "name" && key != "type" && key != "udp" {
			b.warnf("Tailscale proxy %q: field %q is not mapped to sing-box", name, key)
		}
	}
	// The endpoint has no Mihomo-style UDP toggle. Surface the difference
	// rather than inventing an endpoint field rejected by sing-box.
	if !clash.MapGetBool(proxy, "udp", false) {
		b.warnf("Tailscale proxy %q: sing-box endpoints do not support disabling UDP with the Mihomo udp field", name)
	}
	return out
}
