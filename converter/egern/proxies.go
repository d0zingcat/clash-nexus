package egern

import (
	"encoding/base64"
	"strconv"
	"strings"

	"clash-nexus/converter/clash"
)

func egernEndpoint(p map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"name":   clash.MapGetStr(p, "name", ""),
		"server": clash.MapGetStr(p, "server", ""),
		"port":   clash.MapGetInt(p, "port", 0),
	}
}

func egernReality(opts map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{"public_key": clash.MapGetStr(opts, "public-key", "")}
	if shortID := clash.MapGetStr(opts, "short-id", ""); shortID != "" {
		out["short_id"] = shortID
	}
	return out
}

func applyEgernTLS(p, out map[string]interface{}) {
	if sni := clash.MapGetStr(p, "servername", clash.MapGetStr(p, "sni", "")); sni != "" {
		out["sni"] = sni
	}
	// AnyTLS defaults to insecure in Egern. Always emit the Clash default (false).
	out["skip_tls_verify"] = clash.MapGetBool(p, "skip-cert-verify", false)
	if fingerprint := clash.MapGetStr(p, "fingerprint", ""); fingerprint != "" {
		out["fingerprint_sha256"] = fingerprint
		delete(out, "skip_tls_verify")
	}
}

func applyEgernProxyOptions(p, entry map[string]interface{}) {
	for kind, raw := range entry {
		out := raw.(map[string]interface{})
		versions := map[string]string{"dual": "dual_stack", "ipv4": "v4_only", "ipv6": "v6_only", "ipv4-prefer": "v4_prefer", "ipv6-prefer": "v6_prefer"}
		if version := versions[clash.MapGetStr(p, "ip-version", "")]; version != "" {
			out["ip_version"] = version
		}
		switch kind {
		case "shadowsocks", "snell", "trojan", "anytls", "socks5", "socks5_tls", "ssh", "http", "https", "vmess", "vless":
			if _, ok := p["tfo"]; ok {
				out["tfo"] = clash.MapGetBool(p, "tfo", false)
			} else if _, ok := p["fast-open"]; ok {
				out["tfo"] = clash.MapGetBool(p, "fast-open", false)
			}
		}
		switch kind {
		case "trojan", "anytls", "socks5_tls", "https", "hysteria2", "tuic":
			applyEgernTLS(p, out)
		case "vmess", "vless":
			for transportKind, transportRaw := range clash.MapGetMap(out, "transport") {
				if transportKind == "tls" || transportKind == "wss" || transportKind == "http2" || transportKind == "grpc" {
					applyEgernTLS(p, transportRaw.(map[string]interface{}))
				}
			}
		}
		if kind == "trojan" || kind == "https" || kind == "socks5_tls" {
			if opts := clash.MapGetMap(p, "reality-opts"); len(opts) > 0 {
				out["reality"] = egernReality(opts)
			}
		}
		if kind == "http" || kind == "https" {
			if headers := clash.MapGetMap(p, "headers"); len(headers) > 0 {
				out["headers"] = headers
			}
		}
	}
}

func convertAnyTLSToEgern(p map[string]interface{}) map[string]interface{} {
	out := egernEndpoint(p)
	out["password"] = clash.MapGetStr(p, "password", "")
	out["udp_relay"] = clash.MapGetBool(p, "udp", false)
	applyEgernTLS(p, out)
	return map[string]interface{}{"anytls": out}
}

func convertTUICToEgern(p map[string]interface{}, warnings *[]string) map[string]interface{} {
	if clash.MapGetStr(p, "token", "") != "" || clash.MapGetStr(p, "uuid", "") == "" {
		addWarning(warnings, "skipping proxy %q: Egern TUIC requires v5 uuid/password; v4 token authentication is unsupported", clash.MapGetStr(p, "name", ""))
		return nil
	}
	if clash.MapGetBool(p, "disable-sni", false) || clash.MapGetStr(p, "ip", "") != "" {
		addWarning(warnings, "skipping proxy %q: Egern TUIC cannot preserve disable-sni or an explicit server IP override", clash.MapGetStr(p, "name", ""))
		return nil
	}
	out := egernEndpoint(p)
	out["uuid"] = clash.MapGetStr(p, "uuid", "")
	out["password"] = clash.MapGetStr(p, "password", "")
	out["udp_relay_mode"] = clash.MapGetStr(p, "udp-relay-mode", "native")
	if alpn := clash.ToStringSlice(p["alpn"]); len(alpn) > 0 {
		out["alpn"] = alpn
	}
	return map[string]interface{}{"tuic": out}
}

func convertSnellToEgern(p map[string]interface{}, warnings *[]string) map[string]interface{} {
	version := clash.MapGetInt(p, "version", 1)
	opts := clash.MapGetMap(p, "obfs-opts")
	mode := clash.MapGetStr(opts, "mode", "")
	if version < 1 || version > 4 || (mode != "" && mode != "http" && mode != "tls") {
		addWarning(warnings, "skipping proxy %q: Egern Snell supports v1-v4 with http/tls obfuscation; v5 is only a v4 alias", clash.MapGetStr(p, "name", ""))
		return nil
	}
	out := egernEndpoint(p)
	out["psk"] = clash.MapGetStr(p, "psk", "")
	out["version"] = version
	out["udp_relay"] = version >= 3 && clash.MapGetBool(p, "udp", false)
	if version == 4 {
		out["reuse"] = clash.MapGetBool(p, "reuse", false)
	}
	if mode != "" {
		out["obfs"] = mode
		if host := clash.MapGetStr(opts, "host", ""); host != "" {
			out["obfs_host"] = host
		}
	}
	return map[string]interface{}{"snell": out}
}

func convertWireGuardToEgern(p map[string]interface{}, warnings *[]string) map[string]interface{} {
	// Egern has a single peer and no allowed-IP routing or AmneziaWG fields.
	if len(clash.ToMapSlice(p["peers"])) > 0 || p["amnezia-wg-option"] != nil || !egernDefaultAllowedIPs(p["allowed-ips"]) {
		addWarning(warnings, "skipping proxy %q: Egern WireGuard cannot preserve peers, restricted allowed-ips, or AmneziaWG options", clash.MapGetStr(p, "name", ""))
		return nil
	}
	out := egernEndpoint(p)
	for source, target := range map[string]string{"private-key": "private_key", "public-key": "peer_public_key", "pre-shared-key": "preshared_key", "ip": "local_ipv4", "ipv6": "local_ipv6"} {
		if value := clash.MapGetStr(p, source, ""); value != "" {
			out[target] = value
		}
	}
	if out["local_ipv4"] == nil && out["local_ipv6"] == nil {
		addWarning(warnings, "skipping proxy %q: Egern WireGuard requires a local IPv4 or IPv6 address", clash.MapGetStr(p, "name", ""))
		return nil
	}
	if reserved, ok := p["reserved"]; ok {
		var bytes []int
		if encoded, ok := reserved.(string); ok {
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err == nil {
				for _, b := range decoded {
					bytes = append(bytes, int(b))
				}
			}
		} else {
			for _, value := range clash.ToStringSlice(reserved) {
				n, err := strconv.Atoi(value)
				if err != nil || n < 0 || n > 255 {
					bytes = nil
					break
				}
				bytes = append(bytes, n)
			}
		}
		if len(bytes) != 3 {
			addWarning(warnings, "skipping proxy %q: WireGuard reserved must contain exactly three bytes", clash.MapGetStr(p, "name", ""))
			return nil
		}
		out["reserved"] = bytes
	}
	if mtu := clash.MapGetInt(p, "mtu", 0); mtu > 0 {
		out["mtu"] = mtu
	}
	if keepalive := clash.MapGetInt(p, "persistent-keepalive", clash.MapGetInt(p, "keepalive", 0)); keepalive > 0 {
		out["keepalive"] = keepalive
	}
	if clash.MapGetBool(p, "remote-dns-resolve", false) {
		if dns := clash.ToStringSlice(p["dns"]); len(dns) > 0 {
			out["dns_servers"] = dns
		}
	}
	return map[string]interface{}{"wireguard": out}
}

func egernDefaultAllowedIPs(raw interface{}) bool {
	for _, prefix := range clash.ToStringSlice(raw) {
		if prefix != "0.0.0.0/0" && prefix != "::/0" {
			return false
		}
	}
	return true
}

func convertSSHToEgern(p map[string]interface{}, warnings *[]string) map[string]interface{} {
	key := clash.MapGetStr(p, "private-key", "")
	if clash.MapGetStr(p, "private-key-passphrase", "") != "" || strings.Contains(key, "ENCRYPTED") || (key != "" && !strings.Contains(key, "-----BEGIN")) {
		addWarning(warnings, "skipping proxy %q: Egern SSH requires an unencrypted inline private key", clash.MapGetStr(p, "name", ""))
		return nil
	}
	out := egernEndpoint(p)
	out["port"] = clash.MapGetInt(p, "port", 22)
	out["username"] = clash.MapGetStr(p, "username", "")
	for source, target := range map[string]string{"password": "password", "private-key": "private_key"} {
		if value := clash.MapGetStr(p, source, ""); value != "" {
			out[target] = value
		}
	}
	if keys := clash.ToStringSlice(p["host-key"]); len(keys) > 0 {
		out["host_keys"] = keys
	}
	return map[string]interface{}{"ssh": out}
}
