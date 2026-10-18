package singbox

import (
	"strings"

	"clash-nexus/converter/clash"
)

func (b *builder) buildInbounds() []interface{} {
	inbounds := []interface{}{}
	listen := b.listenAddress()
	users := buildUsers(b.config["authentication"])

	mixedPort := mapInt(b.config, "mixed-port", 0)
	httpPort := mapInt(b.config, "port", 0)
	socksPort := mapInt(b.config, "socks-port", 0)
	redirPort := mapInt(b.config, "redir-port", 0)
	tproxyPort := mapInt(b.config, "tproxy-port", 0)

	if mixedPort > 0 {
		inbound := map[string]interface{}{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      listen,
			"listen_port": mixedPort,
		}
		if len(users) > 0 {
			inbound["users"] = users
		}
		inbounds = append(inbounds, inbound)
	}
	if httpPort > 0 {
		inbound := map[string]interface{}{
			"type":        "http",
			"tag":         "http-in",
			"listen":      listen,
			"listen_port": httpPort,
		}
		if len(users) > 0 {
			inbound["users"] = users
		}
		inbounds = append(inbounds, inbound)
	}
	if socksPort > 0 {
		inbound := map[string]interface{}{
			"type":        "socks",
			"tag":         "socks-in",
			"listen":      listen,
			"listen_port": socksPort,
		}
		if len(users) > 0 {
			inbound["users"] = users
		}
		inbounds = append(inbounds, inbound)
	}
	if redirPort > 0 {
		inbounds = append(inbounds, map[string]interface{}{
			"type":        "redirect",
			"tag":         "redirect-in",
			"listen":      listen,
			"listen_port": redirPort,
		})
	}
	if tproxyPort > 0 {
		inbounds = append(inbounds, map[string]interface{}{
			"type":        "tproxy",
			"tag":         "tproxy-in",
			"listen":      listen,
			"listen_port": tproxyPort,
		})
	}

	if tun := b.buildTUNInbound(); tun != nil {
		inbounds = append(inbounds, tun)
	}
	return inbounds
}

func (b *builder) listenAddress() string {
	if raw := strings.TrimSpace(clash.MapGetStr(b.config, "bind-address", "")); raw != "" {
		switch raw {
		case "*":
			return "0.0.0.0"
		default:
			return raw
		}
	}
	if clash.MapGetBool(b.config, "allow-lan", false) {
		return "0.0.0.0"
	}
	return "127.0.0.1"
}

func buildUsers(raw interface{}) []interface{} {
	entries := toStringSlice(raw)
	users := make([]interface{}, 0, len(entries))
	for _, entry := range entries {
		username, password, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok || strings.TrimSpace(username) == "" {
			continue
		}
		users = append(users, map[string]interface{}{
			"username": strings.TrimSpace(username),
			"password": password,
		})
	}
	return users
}

func (b *builder) buildTUNInbound() map[string]interface{} {
	tun := clash.MapGetMap(b.config, "tun")
	if len(tun) == 0 || !clash.MapGetBool(tun, "enable", false) {
		return nil
	}
	inbound := map[string]interface{}{
		"type": "tun",
		"tag":  "tun-in",
	}
	addresses := toStringSlice(tun["address"])
	if len(addresses) == 0 {
		if values := toStringSlice(tun["inet4-address"]); len(values) > 0 {
			addresses = append(addresses, values...)
		} else {
			addresses = append(addresses, "172.19.0.1/30")
		}
		if values := toStringSlice(tun["inet6-address"]); len(values) > 0 {
			addresses = append(addresses, values...)
		} else if clash.MapGetBool(b.config, "ipv6", false) {
			addresses = append(addresses, "fdfe:dcba:9876::1/126")
		}
	}
	inbound["address"] = addresses
	if iface := firstString(tun, "device", "interface-name"); iface != "" {
		inbound["interface_name"] = iface
	}
	if mtu := mapInt(tun, "mtu", 0); mtu > 0 {
		inbound["mtu"] = mtu
	}
	if stack := strings.ToLower(strings.TrimSpace(clash.MapGetStr(tun, "stack", ""))); stack != "" {
		switch stack {
		case "system", "gvisor", "mixed":
			inbound["stack"] = stack
		default:
			b.warnf("tun.stack %q is not supported by sing-box, using system", stack)
			inbound["stack"] = "system"
		}
	}
	if clash.MapGetBool(tun, "auto-route", false) {
		inbound["auto_route"] = true
	}
	if clash.MapGetBool(tun, "strict-route", false) {
		inbound["strict_route"] = true
	}
	if clash.MapGetBool(tun, "auto-redirect", false) {
		b.warnf("tun.auto-redirect is only supported by sing-box on Linux")
		inbound["auto_redirect"] = true
	}
	return inbound
}
