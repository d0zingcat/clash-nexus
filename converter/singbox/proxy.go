package singbox

import (
	"fmt"
	"strconv"
	"strings"

	"clash-nexus/converter/clash"
)

func (b *builder) buildProxy(proxy map[string]interface{}) map[string]interface{} {
	name := strings.TrimSpace(clash.MapGetStr(proxy, "name", ""))
	if name == "" {
		b.warnf("skipping proxy: missing required field \"name\"")
		return nil
	}
	proxyType := strings.ToLower(strings.TrimSpace(clash.MapGetStr(proxy, "type", "")))
	if proxyType == "" {
		b.warnf("skipping proxy %q: missing required field \"type\"", name)
		return nil
	}
	if proxyType == "direct" {
		outbound := map[string]interface{}{"type": "direct", "tag": name}
		b.applyDialFields(proxy, outbound)
		return outbound
	}

	server := strings.TrimSpace(clash.MapGetStr(proxy, "server", ""))
	port := mapInt(proxy, "port", 0)
	if server == "" || port <= 0 {
		b.warnf("skipping proxy %q (type: %s): missing server or port", name, proxyType)
		return nil
	}

	var outbound map[string]interface{}
	switch proxyType {
	case "ss":
		outbound = b.convertShadowsocks(proxy, name, server, port)
	case "vmess":
		outbound = b.convertVMess(proxy, name, server, port)
	case "vless":
		outbound = b.convertVLESS(proxy, name, server, port)
	case "trojan":
		outbound = b.convertTrojan(proxy, name, server, port)
	case "hysteria2":
		outbound = b.convertHysteria2(proxy, name, server, port)
	case "hysteria":
		outbound = b.convertHysteria(proxy, name, server, port)
	case "tuic":
		outbound = b.convertTUIC(proxy, name, server, port)
	case "socks5", "socks":
		outbound = b.convertSocks(proxy, name, server, port)
	case "http":
		outbound = b.convertHTTP(proxy, name, server, port)
	case "anytls":
		outbound = b.convertAnyTLS(proxy, name, server, port)
	case "snell":
		outbound = b.convertSnell(proxy, name, server, port)
	default:
		b.warnf("skipping proxy %q: type %q is not supported by sing-box", name, proxyType)
		return nil
	}
	if outbound == nil {
		return nil
	}
	b.applyDialFields(proxy, outbound)
	b.warnProxyFields(proxy, outbound, proxyType, name)
	return outbound
}

func baseOutbound(typ, name, server string, port int) map[string]interface{} {
	return map[string]interface{}{
		"type":        typ,
		"tag":         name,
		"server":      server,
		"server_port": port,
	}
}

func (b *builder) convertShadowsocks(proxy map[string]interface{}, name, server string, port int) map[string]interface{} {
	method := strings.TrimSpace(clash.MapGetStr(proxy, "cipher", ""))
	password := clash.MapGetStr(proxy, "password", "")
	if method == "" || password == "" {
		b.warnf("skipping proxy %q (type: ss): missing cipher or password", name)
		return nil
	}
	outbound := baseOutbound("shadowsocks", name, server, port)
	outbound["method"] = method
	outbound["password"] = password

	plugin := strings.ToLower(strings.TrimSpace(clash.MapGetStr(proxy, "plugin", "")))
	pluginOpts := clash.MapGetMap(proxy, "plugin-opts")
	switch plugin {
	case "":
	case "obfs":
		mode := strings.TrimSpace(clash.MapGetStr(pluginOpts, "mode", "http"))
		host := strings.TrimSpace(clash.MapGetStr(pluginOpts, "host", ""))
		opts := "obfs=" + mode
		if host != "" {
			opts += ";obfs-host=" + host
		}
		outbound["plugin"] = "obfs-local"
		outbound["plugin_opts"] = opts
	case "v2ray-plugin":
		mode := strings.TrimSpace(clash.MapGetStr(pluginOpts, "mode", "websocket"))
		host := strings.TrimSpace(clash.MapGetStr(pluginOpts, "host", ""))
		path := strings.TrimSpace(clash.MapGetStr(pluginOpts, "path", ""))
		tls := clash.MapGetBool(pluginOpts, "tls", false)
		opts := "mode=" + mode
		if host != "" {
			opts += ";host=" + host
		}
		if path != "" {
			opts += ";path=" + path
		}
		if tls {
			opts += ";tls"
		}
		outbound["plugin"] = "v2ray-plugin"
		outbound["plugin_opts"] = opts
	default:
		b.warnf("skipping proxy %q (type: ss): plugin %q is not supported by sing-box", name, plugin)
		return nil
	}

	if !clash.MapGetBool(proxy, "udp", false) {
		outbound["network"] = "tcp"
	}
	return outbound
}

func (b *builder) convertVMess(proxy map[string]interface{}, name, server string, port int) map[string]interface{} {
	uuid := strings.TrimSpace(clash.MapGetStr(proxy, "uuid", ""))
	if uuid == "" {
		b.warnf("skipping proxy %q (type: vmess): missing uuid", name)
		return nil
	}
	outbound := baseOutbound("vmess", name, server, port)
	outbound["uuid"] = uuid
	outbound["security"] = defaultString(clash.MapGetStr(proxy, "cipher", ""), "auto")
	if alterID := mapInt(proxy, "alterId", 0); alterID > 0 {
		outbound["alter_id"] = alterID
	}
	if packetEncoding := strings.TrimSpace(clash.MapGetStr(proxy, "packet-encoding", "")); packetEncoding != "" {
		outbound["packet_encoding"] = packetEncoding
	}
	b.attachTLSAndTransport(proxy, outbound, false)
	if !clash.MapGetBool(proxy, "udp", false) {
		outbound["network"] = "tcp"
	}
	return outbound
}

func (b *builder) convertVLESS(proxy map[string]interface{}, name, server string, port int) map[string]interface{} {
	uuid := strings.TrimSpace(clash.MapGetStr(proxy, "uuid", ""))
	if uuid == "" {
		b.warnf("skipping proxy %q (type: vless): missing uuid", name)
		return nil
	}
	outbound := baseOutbound("vless", name, server, port)
	outbound["uuid"] = uuid
	if flow := strings.TrimSpace(clash.MapGetStr(proxy, "flow", "")); flow != "" {
		outbound["flow"] = flow
	}
	if packetEncoding := strings.TrimSpace(clash.MapGetStr(proxy, "packet-encoding", "")); packetEncoding != "" {
		outbound["packet_encoding"] = packetEncoding
	}
	b.attachTLSAndTransport(proxy, outbound, false)
	if !clash.MapGetBool(proxy, "udp", false) {
		outbound["network"] = "tcp"
	}
	return outbound
}

func (b *builder) convertTrojan(proxy map[string]interface{}, name, server string, port int) map[string]interface{} {
	password := clash.MapGetStr(proxy, "password", "")
	if password == "" {
		b.warnf("skipping proxy %q (type: trojan): missing password", name)
		return nil
	}
	outbound := baseOutbound("trojan", name, server, port)
	outbound["password"] = password
	b.attachTLSAndTransport(proxy, outbound, true)
	if !clash.MapGetBool(proxy, "udp", false) {
		outbound["network"] = "tcp"
	}
	return outbound
}

func (b *builder) convertHysteria2(proxy map[string]interface{}, name, server string, port int) map[string]interface{} {
	password := firstString(proxy, "password", "auth")
	if password == "" {
		b.warnf("skipping proxy %q (type: hysteria2): missing password/auth", name)
		return nil
	}
	outbound := baseOutbound("hysteria2", name, server, port)
	outbound["password"] = password
	if ports := portRanges(proxy["ports"]); len(ports) > 0 {
		delete(outbound, "server_port")
		outbound["server_ports"] = ports
		if hop := mapInt(proxy, "hop-interval", 0); hop > 0 {
			outbound["hop_interval"] = durationSeconds(hop)
		}
	}
	if up := speedField(proxy, "up", "up-speed"); up > 0 {
		outbound["up_mbps"] = up
	}
	if down := speedField(proxy, "down", "down-speed"); down > 0 {
		outbound["down_mbps"] = down
	}
	obfsType := strings.TrimSpace(clash.MapGetStr(proxy, "obfs", ""))
	if obfsType != "" {
		obfs := map[string]interface{}{"type": obfsType}
		if password := clash.MapGetStr(proxy, "obfs-password", ""); password != "" {
			obfs["password"] = password
		}
		outbound["obfs"] = obfs
	}
	if tls := b.buildTLS(proxy, true); tls != nil {
		outbound["tls"] = tls
	}
	return outbound
}

func (b *builder) convertHysteria(proxy map[string]interface{}, name, server string, port int) map[string]interface{} {
	authStr := clash.MapGetStr(proxy, "auth-str", "")
	auth := clash.MapGetStr(proxy, "auth", "")
	if authStr == "" && auth == "" {
		b.warnf("skipping proxy %q (type: hysteria): missing auth or auth-str", name)
		return nil
	}
	outbound := baseOutbound("hysteria", name, server, port)
	if authStr != "" {
		outbound["auth_str"] = authStr
	}
	if auth != "" {
		outbound["auth"] = auth
	}
	if up := speedField(proxy, "up", "up-speed"); up > 0 {
		outbound["up_mbps"] = up
	}
	if down := speedField(proxy, "down", "down-speed"); down > 0 {
		outbound["down_mbps"] = down
	}
	if obfs := strings.TrimSpace(clash.MapGetStr(proxy, "obfs", "")); obfs != "" {
		outbound["obfs"] = obfs
	}
	if ports := portRanges(proxy["ports"]); len(ports) > 0 {
		delete(outbound, "server_port")
		outbound["server_ports"] = ports
		if hop := mapInt(proxy, "hop-interval", 0); hop > 0 {
			outbound["hop_interval"] = durationSeconds(hop)
		}
	}
	if tls := b.buildTLS(proxy, true); tls != nil {
		outbound["tls"] = tls
	}
	return outbound
}

func (b *builder) convertTUIC(proxy map[string]interface{}, name, server string, port int) map[string]interface{} {
	uuid := strings.TrimSpace(clash.MapGetStr(proxy, "uuid", ""))
	if uuid == "" {
		b.warnf("skipping proxy %q (type: tuic): missing uuid", name)
		return nil
	}
	outbound := baseOutbound("tuic", name, server, port)
	outbound["uuid"] = uuid
	if password := clash.MapGetStr(proxy, "password", ""); password != "" {
		outbound["password"] = password
	}
	if cc := firstString(proxy, "congestion-controller", "congestion_control"); cc != "" {
		outbound["congestion_control"] = cc
	}
	if mode := firstString(proxy, "udp-relay-mode", "udp_relay_mode"); mode != "" {
		outbound["udp_relay_mode"] = mode
	}
	if clash.MapGetBool(proxy, "udp-over-stream", false) {
		outbound["udp_over_stream"] = true
	}
	if clash.MapGetBool(proxy, "reduce-rtt", false) {
		outbound["zero_rtt_handshake"] = true
	}
	if heartbeat := mapInt(proxy, "heartbeat-interval", 0); heartbeat > 0 {
		outbound["heartbeat"] = durationSeconds(heartbeat)
	}
	if tls := b.buildTLS(proxy, true); tls != nil {
		if clash.MapGetBool(proxy, "disable-sni", false) {
			tls["disable_sni"] = true
		}
		outbound["tls"] = tls
	}
	return outbound
}

func (b *builder) buildWireGuardEndpoint(proxy map[string]interface{}) map[string]interface{} {
	name := strings.TrimSpace(clash.MapGetStr(proxy, "name", ""))
	if name == "" {
		b.warnf("skipping proxy: missing required field \"name\"")
		return nil
	}
	server := strings.TrimSpace(clash.MapGetStr(proxy, "server", ""))
	port := mapInt(proxy, "port", 0)
	if server == "" || port <= 0 {
		b.warnf("skipping proxy %q (type: wireguard): missing server or port", name)
		return nil
	}
	privateKey := strings.TrimSpace(clash.MapGetStr(proxy, "private-key", ""))
	publicKey := strings.TrimSpace(clash.MapGetStr(proxy, "public-key", ""))
	if privateKey == "" || publicKey == "" {
		b.warnf("skipping proxy %q (type: wireguard): missing private-key or public-key", name)
		return nil
	}
	localAddress := append(toStringSlice(proxy["ip"]), toStringSlice(proxy["ipv6"])...)
	if len(localAddress) == 0 {
		b.warnf("skipping proxy %q (type: wireguard): missing local ip address", name)
		return nil
	}
	peer := map[string]interface{}{
		"address":     server,
		"port":        port,
		"public_key":  publicKey,
		"allowed_ips": []string{"0.0.0.0/0", "::/0"},
	}
	if allowed := toStringSlice(proxy["allowed-ips"]); len(allowed) > 0 {
		peer["allowed_ips"] = allowed
	}
	if psk := strings.TrimSpace(clash.MapGetStr(proxy, "preshared-key", "")); psk != "" {
		peer["pre_shared_key"] = psk
	}
	if reserved := intSlice(proxy["reserved"]); len(reserved) > 0 {
		peer["reserved"] = reserved
	}
	if keepalive := mapInt(proxy, "persistent-keepalive", 0); keepalive > 0 {
		peer["persistent_keepalive_interval"] = keepalive
	}

	endpoint := map[string]interface{}{
		"type":        "wireguard",
		"tag":         name,
		"address":     localAddress,
		"private_key": privateKey,
		"peers":       []interface{}{peer},
	}
	if mtu := mapInt(proxy, "mtu", 0); mtu > 0 {
		endpoint["mtu"] = mtu
	}
	if workers := mapInt(proxy, "workers", 0); workers > 0 {
		endpoint["workers"] = workers
	}
	b.applyDialFields(proxy, endpoint)
	b.warnProxyFields(proxy, endpoint, "wireguard", name)
	return endpoint
}

func (b *builder) convertSocks(proxy map[string]interface{}, name, server string, port int) map[string]interface{} {
	outbound := baseOutbound("socks", name, server, port)
	outbound["version"] = "5"
	if username := clash.MapGetStr(proxy, "username", ""); username != "" {
		outbound["username"] = username
	}
	if password := clash.MapGetStr(proxy, "password", ""); password != "" {
		outbound["password"] = password
	}
	if !clash.MapGetBool(proxy, "udp", false) {
		outbound["network"] = "tcp"
	}
	return outbound
}

func (b *builder) convertHTTP(proxy map[string]interface{}, name, server string, port int) map[string]interface{} {
	outbound := baseOutbound("http", name, server, port)
	if username := clash.MapGetStr(proxy, "username", ""); username != "" {
		outbound["username"] = username
	}
	if password := clash.MapGetStr(proxy, "password", ""); password != "" {
		outbound["password"] = password
	}
	if headers := clash.MapGetMap(proxy, "headers"); len(headers) > 0 {
		outbound["headers"] = headers
	}
	if tls := b.buildTLS(proxy, false); tls != nil {
		outbound["tls"] = tls
	}
	return outbound
}

func (b *builder) convertAnyTLS(proxy map[string]interface{}, name, server string, port int) map[string]interface{} {
	password := clash.MapGetStr(proxy, "password", "")
	if password == "" {
		b.warnf("skipping proxy %q (type: anytls): missing password", name)
		return nil
	}
	outbound := baseOutbound("anytls", name, server, port)
	outbound["password"] = password
	if interval := mapInt(proxy, "idle-session-check-interval", 0); interval > 0 {
		outbound["idle_session_check_interval"] = durationSeconds(interval)
	}
	if timeout := mapInt(proxy, "idle-session-timeout", 0); timeout > 0 {
		outbound["idle_session_timeout"] = durationSeconds(timeout)
	}
	if min := mapInt(proxy, "min-idle-session", 0); min > 0 {
		outbound["min_idle_session"] = min
	}
	if tls := b.buildTLS(proxy, true); tls != nil {
		outbound["tls"] = tls
	}
	return outbound
}

func (b *builder) convertSnell(proxy map[string]interface{}, name, server string, port int) map[string]interface{} {
	psk := clash.MapGetStr(proxy, "psk", "")
	if psk == "" {
		b.warnf("skipping proxy %q (type: snell): missing psk", name)
		return nil
	}
	version := mapInt(proxy, "version", 0)
	if version != 4 && version != 6 {
		b.warnf("skipping proxy %q (type: snell): sing-box only supports Snell v4/v6, got %d", name, version)
		return nil
	}
	outbound := baseOutbound("snell", name, server, port)
	outbound["version"] = version
	outbound["psk"] = psk
	if version == 4 || version == 6 {
		b.warnf("proxy %q: snell outbound requires sing-box 1.14 or newer", name)
	}
	if userkey := strings.TrimSpace(clash.MapGetStr(proxy, "userkey", "")); userkey != "" {
		outbound["userkey"] = userkey
	}
	obfs := clash.MapGetMap(proxy, "obfs-opts")
	if mode := strings.TrimSpace(clash.MapGetStr(obfs, "mode", "")); mode != "" {
		outbound["obfs_mode"] = mode
	}
	if host := strings.TrimSpace(clash.MapGetStr(obfs, "host", "")); host != "" {
		outbound["obfs_host"] = host
	}
	if !clash.MapGetBool(proxy, "udp", false) {
		outbound["network"] = "tcp"
	}
	return outbound
}

// ---------------------------------------------------------------------------
// Shared TLS / transport / dial fields
// ---------------------------------------------------------------------------

func (b *builder) attachTLSAndTransport(proxy map[string]interface{}, outbound map[string]interface{}, tlsRequired bool) {
	if tls := b.buildTLS(proxy, tlsRequired); tls != nil {
		outbound["tls"] = tls
	}
	if transport := b.buildTransport(proxy); transport != nil {
		outbound["transport"] = transport
	}
}

func (b *builder) buildTLS(proxy map[string]interface{}, required bool) map[string]interface{} {
	realityOpts := clash.MapGetMap(proxy, "reality-opts")
	enabled := required || clash.MapGetBool(proxy, "tls", false) || realityOpts != nil
	if !enabled {
		return nil
	}
	tls := map[string]interface{}{"enabled": true}
	if sni := firstString(proxy, "servername", "sni", "server-name"); sni != "" {
		tls["server_name"] = sni
	}
	if clash.MapGetBool(proxy, "skip-cert-verify", false) {
		tls["insecure"] = true
	}
	if alpn := toStringSlice(proxy["alpn"]); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	fingerprint := firstString(proxy, "client-fingerprint", "client_fingerprint")
	if fingerprint == "" {
		fingerprint = b.globalFingerprint
	}
	if fingerprint == "" && realityOpts != nil {
		// sing-box's Reality client requires uTLS.
		fingerprint = "chrome"
	}
	if fingerprint != "" && fingerprint != "none" {
		tls["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fingerprint,
		}
	}
	if realityOpts != nil {
		publicKey := strings.TrimRight(strings.TrimSpace(clash.MapGetStr(realityOpts, "public-key", "")), "=")
		if publicKey == "" {
			b.warnf("proxy %q: reality-opts has no public-key, reality disabled", clash.MapGetStr(proxy, "name", ""))
		} else {
			reality := map[string]interface{}{
				"enabled":    true,
				"public_key": publicKey,
			}
			if shortID := strings.TrimSpace(clash.MapGetStr(realityOpts, "short-id", "")); shortID != "" {
				reality["short_id"] = shortID
			}
			tls["reality"] = reality
		}
	}
	return tls
}

func (b *builder) buildTransport(proxy map[string]interface{}) map[string]interface{} {
	network := strings.ToLower(strings.TrimSpace(clash.MapGetStr(proxy, "network", "")))
	switch network {
	case "", "tcp":
		return nil
	case "ws":
		opts := clash.MapGetMap(proxy, "ws-opts")
		transport := map[string]interface{}{"type": "ws"}
		if path := strings.TrimSpace(clash.MapGetStr(opts, "path", "")); path != "" {
			transport["path"] = path
		}
		if headers := clash.MapGetMap(opts, "headers"); len(headers) > 0 {
			transport["headers"] = headers
		}
		if maxEarly := mapInt(opts, "max-early-data", 0); maxEarly > 0 {
			transport["max_early_data"] = maxEarly
		}
		if header := strings.TrimSpace(clash.MapGetStr(opts, "early-data-header-name", "")); header != "" {
			transport["early_data_header_name"] = header
		}
		return transport
	case "grpc":
		opts := clash.MapGetMap(proxy, "grpc-opts")
		transport := map[string]interface{}{"type": "grpc"}
		if service := firstString(opts, "grpc-service-name", "service-name", "service_name"); service != "" {
			transport["service_name"] = service
		}
		return transport
	case "h2", "http":
		opts := clash.MapGetMap(proxy, "h2-opts")
		if len(opts) == 0 {
			opts = clash.MapGetMap(proxy, "http-opts")
		}
		transport := map[string]interface{}{"type": "http"}
		if hosts := toStringSlice(opts["host"]); len(hosts) > 0 {
			transport["host"] = hosts
		}
		if paths := toStringSlice(opts["path"]); len(paths) > 0 {
			transport["path"] = paths[0]
		} else if path := firstString(opts, "path"); path != "" {
			transport["path"] = path
		}
		if headers := clash.MapGetMap(opts, "headers"); len(headers) > 0 {
			transport["headers"] = headers
		}
		return transport
	case "httpupgrade":
		opts := clash.MapGetMap(proxy, "httpupgrade-opts")
		transport := map[string]interface{}{"type": "httpupgrade"}
		if host := firstString(opts, "host"); host != "" {
			transport["host"] = host
		}
		if path := firstString(opts, "path"); path != "" {
			transport["path"] = path
		}
		return transport
	case "quic":
		return map[string]interface{}{"type": "quic"}
	default:
		b.warnf("proxy %q: unsupported network %q, transport is omitted", clash.MapGetStr(proxy, "name", ""), network)
		return nil
	}
}

func (b *builder) applyDialFields(proxy map[string]interface{}, outbound map[string]interface{}) {
	if clash.MapGetBool(proxy, "tfo", false) || clash.MapGetBool(proxy, "fast-open", false) {
		outbound["tcp_fast_open"] = true
	}
	if clash.MapGetBool(proxy, "mptcp", false) {
		outbound["tcp_multi_path"] = true
	}
	if dialer := strings.TrimSpace(clash.MapGetStr(proxy, "dialer-proxy", "")); dialer != "" {
		outbound["detour"] = dialer
	}
	if iface := strings.TrimSpace(clash.MapGetStr(proxy, "interface-name", "")); iface != "" {
		outbound["bind_interface"] = iface
	}
	if mark := routingMark(proxy["routing-mark"]); mark > 0 {
		outbound["routing_mark"] = mark
	}
	if clash.MapGetBool(proxy, "udp-over-tcp", false) {
		outbound["udp_over_tcp"] = true
	}
}

// warnProxyFields reports Clash-only proxy fields that were not consumed. It is
// intentionally conservative: fields that are known to be irrelevant to
// sing-box are listed explicitly, everything else is surfaced.
func (b *builder) warnProxyFields(proxy, outbound map[string]interface{}, proxyType, name string) {
	ignored := map[string]bool{
		"name": true, "type": true, "server": true, "port": true,
		"udp": true, "tfo": true, "fast-open": true, "mptcp": true,
		"dialer-proxy": true, "interface-name": true, "routing-mark": true,
		"udp-over-tcp": true,
	}
	switch proxyType {
	case "ss":
		for _, key := range []string{"cipher", "password", "plugin", "plugin-opts"} {
			ignored[key] = true
		}
	case "vmess":
		for _, key := range []string{"uuid", "cipher", "alterId", "packet-encoding"} {
			ignored[key] = true
		}
	case "vless":
		for _, key := range []string{"uuid", "flow", "packet-encoding"} {
			ignored[key] = true
		}
	case "trojan", "anytls":
		ignored["password"] = true
	case "hysteria2":
		for _, key := range []string{"password", "auth", "ports", "hop-interval", "up", "down", "up-speed", "down-speed", "obfs", "obfs-password"} {
			ignored[key] = true
		}
	case "hysteria":
		for _, key := range []string{"auth", "auth-str", "up", "down", "up-speed", "down-speed", "obfs", "ports", "hop-interval"} {
			ignored[key] = true
		}
	case "tuic":
		for _, key := range []string{"uuid", "password", "congestion-controller", "udp-relay-mode", "udp-over-stream", "reduce-rtt", "heartbeat-interval", "disable-sni"} {
			ignored[key] = true
		}
	case "wireguard":
		for _, key := range []string{"ip", "ipv6", "private-key", "public-key", "preshared-key", "reserved", "mtu", "workers", "allowed-ips", "persistent-keepalive"} {
			ignored[key] = true
		}
	case "socks5", "socks":
		for _, key := range []string{"username", "password"} {
			ignored[key] = true
		}
	case "http":
		for _, key := range []string{"username", "password", "headers"} {
			ignored[key] = true
		}
	case "snell":
		for _, key := range []string{"psk", "version", "userkey", "obfs-opts"} {
			ignored[key] = true
		}
	}
	for _, key := range []string{"tls", "sni", "servername", "server-name", "skip-cert-verify", "alpn", "client-fingerprint", "reality-opts", "network"} {
		ignored[key] = true
	}
	for _, key := range []string{"ws-opts", "grpc-opts", "h2-opts", "http-opts", "httpupgrade-opts"} {
		ignored[key] = true
	}
	if proxyType == "http" {
		ignored["reality-opts"] = true
	}

	for _, key := range sortedKeys(proxy) {
		if ignored[key] {
			continue
		}
		b.warnf("proxy %q (type: %s): ignored unsupported field %q", name, proxyType, key)
	}
}

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

func firstString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(clash.MapGetStr(m, key, "")); value != "" {
			return value
		}
	}
	return ""
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func speedField(m map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if value, ok := m[key]; ok {
			if speed := speedMbps(value); speed > 0 {
				return speed
			}
		}
	}
	return 0
}

func speedMbps(v interface{}) int {
	switch value := v.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		s := strings.TrimSpace(strings.ToLower(value))
		s = strings.TrimSuffix(s, "mbps")
		s = strings.TrimSuffix(s, "mb/s")
		s = strings.TrimSuffix(s, "m")
		s = strings.TrimSpace(s)
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	return 0
}

func portRanges(v interface{}) []string {
	var raw []string
	switch value := v.(type) {
	case string:
		raw = strings.Split(value, ",")
	case []interface{}:
		for _, item := range value {
			raw = append(raw, fmt.Sprintf("%v", item))
		}
	case []string:
		raw = value
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		item = strings.ReplaceAll(item, "-", ":")
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func intSlice(v interface{}) []int {
	out := []int{}
	switch value := v.(type) {
	case []interface{}:
		for _, item := range value {
			switch n := item.(type) {
			case int:
				out = append(out, n)
			case int64:
				out = append(out, int(n))
			case float64:
				out = append(out, int(n))
			case string:
				if parsed, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
					out = append(out, parsed)
				}
			}
		}
	case []int:
		out = value
	}
	return out
}
