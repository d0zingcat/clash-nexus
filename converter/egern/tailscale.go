package egern

import (
	"sort"
	"strings"

	"clash-nexus/converter/clash"
)

// Field names and nesting are verified against a user-supplied Egern source
// editor export. Only options with a known Mihomo counterpart are emitted.
func convertTailscaleToEgern(p map[string]interface{}, warnings *[]string) map[string]interface{} {
	name := strings.TrimSpace(clash.MapGetStr(p, "name", ""))
	if name == "" {
		addWarning(warnings, "skipping Tailscale proxy: missing name")
		return nil
	}
	if strings.TrimSpace(clash.MapGetStr(p, "exit-node", "")) == "auto:any" {
		addWarning(warnings, "skipping Tailscale proxy %q: Egern's auto:any exit-node selector is unverified; use an explicit exit node", name)
		return nil
	}
	out := map[string]interface{}{
		"name": name,
		// Mihomo routes only explicitly selected traffic through this node.
		"auto_add_magic_dns_rule": false,
		"interactive_login":       strings.TrimSpace(clash.MapGetStr(p, "auth-key", "")) == "",
	}
	fields := map[string]string{
		"auth-key": "auth_key", "control-url": "control_url",
		"hostname": "hostname", "exit-node": "exit_node",
	}
	for _, key := range []string{"auth-key", "control-url", "hostname", "exit-node"} {
		if value := clash.MapGetStr(p, key, ""); value != "" {
			out[fields[key]] = value
		}
	}
	version := clash.MapGetStr(p, "ip-version", "")
	switch version {
	case "ipv6-prefer":
		out["prefer_ipv6"] = true
	case "ipv4-prefer":
		out["prefer_ipv6"] = false
	case "", "dual":
	default:
		addWarning(warnings, "Tailscale proxy %q: Egern prefer_ipv6 cannot preserve ip-version %q", name, version)
	}
	keys := make([]string, 0, len(p))
	for key := range p {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, mapped := fields[key]; mapped {
			continue
		}
		switch key {
		case "name", "type", "dialer-proxy", "ip-version", "udp":
			continue
		default:
			addWarning(warnings, "Tailscale proxy %q: field %q has no verified Egern mapping and was omitted", name, key)
		}
	}
	if !clash.MapGetBool(p, "udp", false) {
		addWarning(warnings, "Tailscale proxy %q: Egern has no verified equivalent for disabling UDP with the Mihomo udp field", name)
	}
	return map[string]interface{}{"tailscale": out}
}
