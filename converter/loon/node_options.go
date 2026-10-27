package loon

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"clash-nexus/converter/clash"
)

func loonQuote(value string) string { return strconv.Quote(value) }

var loonBandwidthPattern = regexp.MustCompile(`(?i)^\s*(\d+(?:\.\d+)?)\s*(bps|kbps|mbps|gbps)?\s*$`)

func loonBandwidthMbps(raw interface{}) (string, bool) {
	if raw == nil {
		return "", false
	}
	match := loonBandwidthPattern.FindStringSubmatch(fmt.Sprint(raw))
	if len(match) == 0 {
		return "", false
	}
	value, err := strconv.ParseFloat(match[1], 64)
	if err != nil || value <= 0 {
		return "", false
	}
	switch strings.ToLower(match[2]) {
	case "bps":
		value /= 1e6
	case "kbps":
		value /= 1e3
	case "gbps":
		value *= 1e3
	}
	return strconv.FormatFloat(value, 'f', -1, 64), true
}

// Node DNS is distinct from ordinary DNS. Loon 3.5.2 (996)+ can retain the
// Clash proxy-server-nameserver list without changing global resolvers.
func loonServerDNS(config map[string]interface{}) ([]string, []string) {
	dns := clash.MapGetMap(config, "dns")
	var servers, warnings []string
	if len(clash.MapGetMap(dns, "proxy-server-nameserver-policy")) > 0 {
		return nil, []string{"Loon server-dns cannot preserve proxy-server-nameserver-policy; configure per-node DNS manually"}
	}
	for _, server := range clash.ToStringSlice(dns["proxy-server-nameserver"]) {
		if !loonNodeDNSServer(server) {
			warnings = append(warnings, fmt.Sprintf("Loon server-dns cannot preserve proxy-server-nameserver %q; configure node DNS manually", server))
			continue
		}
		servers = append(servers, server)
	}
	if len(warnings) > 0 {
		// Partial DNS lists can change the intended resolver path.
		return nil, warnings
	}
	return servers, warnings
}

func loonNodeDNSServer(server string) bool {
	if server == "system" || net.ParseIP(strings.Trim(server, "[]")) != nil {
		return true
	}
	if host, port, err := net.SplitHostPort(server); err == nil && net.ParseIP(host) != nil {
		n, err := strconv.Atoi(port)
		return err == nil && n > 0 && n <= 65535
	}
	u, err := url.Parse(server)
	if err != nil || u.Hostname() == "" || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "quic" || u.Scheme == "h3"
}

func appendLoonNodeOptions(line string, p map[string]interface{}, serverDNS []string) string {
	ptype := strings.ToLower(clash.MapGetStr(p, "type", ""))
	parts := []string{line}
	if len(serverDNS) > 0 {
		parts = append(parts, "server-dns="+loonQuote(strings.Join(serverDNS, ",")))
	}
	if ptype != "wireguard" {
		modes := map[string]string{"dual": "dual", "ipv4": "v4-only", "ipv6": "v6-only", "ipv4-prefer": "prefer-v4", "ipv6-prefer": "prefer-v6"}
		if mode := modes[clash.MapGetStr(p, "ip-version", "")]; mode != "" {
			parts = append(parts, "ip-mode="+mode)
		}
		if !strings.Contains(line, ",fast-open=") {
			if _, ok := p["tfo"]; ok {
				parts = append(parts, "fast-open="+clash.BoolStr(clash.MapGetBool(p, "tfo", false)))
			}
		}
	}
	tls := ptype == "trojan" || ptype == "anytls" || ptype == "hysteria2" || clash.MapGetBool(p, "tls", false) || len(clash.MapGetMap(p, "reality-opts")) > 0
	if tls {
		if !strings.Contains(line, ",sni=") {
			if sni := firstNonEmpty(clash.MapGetStr(p, "servername", ""), clash.MapGetStr(p, "sni", "")); sni != "" {
				parts = append(parts, "sni="+sni)
			}
		}
		if fingerprint := clash.MapGetStr(p, "fingerprint", ""); fingerprint != "" {
			parts = append(parts, "tls-cert-sha256="+fingerprint)
		}
		if ptype != "hysteria2" && !strings.Contains(line, ",tls-profile=") {
			if profile := loonTLSProfile(clash.MapGetStr(p, "client-fingerprint", "")); profile != "" {
				parts = append(parts, "tls-profile="+profile)
			}
		}
		if (ptype == "trojan" || ptype == "hysteria2") && len(clash.ToStringSlice(p["alpn"])) > 0 {
			parts = append(parts, "alpn="+loonQuote(strings.Join(clash.ToStringSlice(p["alpn"]), ",")))
		}
	}
	if ptype == "trojan" || ptype == "vmess" {
		if reality := clash.MapGetMap(p, "reality-opts"); len(reality) > 0 {
			parts = append(parts, "public-key="+loonQuote(clash.MapGetStr(reality, "public-key", "")))
			if shortID := clash.MapGetStr(reality, "short-id", ""); shortID != "" {
				parts = append(parts, "short-id="+shortID)
			}
		}
	}
	return strings.Join(parts, ",")
}

func loonProxyUnsupportedReason(p map[string]interface{}) string {
	ptype := strings.ToLower(clash.MapGetStr(p, "type", ""))
	if ptype == "vmess" || ptype == "vless" || ptype == "trojan" {
		switch clash.MapGetStr(p, "network", "tcp") {
		case "", "tcp", "ws", "http":
		default:
			return "Loon only documents tcp/ws/http transports; the configured transport cannot be preserved"
		}
		if ptype == "trojan" && clash.MapGetStr(p, "network", "tcp") == "http" {
			return "Loon treats Trojan transport=http as WebSocket; Clash HTTP transport is not equivalent"
		}
	}
	if ptype == "hysteria2" {
		if obfs := clash.MapGetStr(p, "obfs", ""); obfs != "" && obfs != "salamander" {
			return "Loon only documents Hysteria2 salamander obfuscation"
		}
		if raw, ok := p["hop-interval"]; ok {
			if interval := clash.MapGetInt(p, "hop-interval", -1); interval <= 0 || strings.Contains(fmt.Sprint(raw), "-") {
				return "Loon cannot preserve a nonpositive or randomized Hysteria2 hop interval"
			}
		}
		if realm := clash.MapGetMap(p, "realm-opts"); clash.MapGetBool(realm, "enable", false) {
			return "Loon has no documented Hysteria2 Realm configuration"
		}
	}
	if ptype == "wireguard" && p["amnezia-wg-option"] != nil {
		return "Loon has no documented AmneziaWG configuration"
	}
	return ""
}

// Current Loon subscriptions may carry node DNS and Host Maps together with
// nodes. Reject unrelated sections so a full client configuration is not
// mistaken for a subscription.
func validLoonTextSubscription(content string) bool {
	section, nodes := "", 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line)
			if section != "[general]" && section != "[host]" && section != "[proxy]" {
				return false
			}
			continue
		}
		if section == "[general]" || section == "[host]" {
			continue
		}
		isNode := false
		for _, prefix := range proxyURIPrefixes {
			if strings.HasPrefix(line, prefix) {
				isNode = true
				break
			}
		}
		if !isNode {
			_, node, ok := strings.Cut(line, "=")
			if !ok {
				return false
			}
			kind, _, ok := strings.Cut(strings.TrimSpace(node), ",")
			if !ok {
				return false
			}
			switch strings.ToLower(kind) {
			case "shadowsocks", "shadowsocksr", "vmess", "vless", "trojan", "http", "https", "socks5", "hysteria2", "anytls", "wireguard", "custom":
				isNode = true
			}
		}
		if !isNode {
			return false
		}
		nodes++
	}
	return nodes > 0
}
