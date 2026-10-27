// Package loon converts a Clash (mihomo) YAML config to a Loon .conf file.
package loon

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"clash-nexus/converter"
	"clash-nexus/converter/clash"
)

// Converter converts Clash YAML to Loon .conf format.
type Converter struct{}

// New returns a new Loon Converter.
func New() *Converter { return &Converter{} }

// Name returns the short identifier for this converter.
func (c *Converter) Name() string { return "loon" }

// DefaultExtension returns the file extension for Loon configs.
func (c *Converter) DefaultExtension() string { return ".conf" }

// Convert transforms a Clash config map into a Loon .conf byte slice.
func (c *Converter) Convert(config map[string]interface{}, root *yaml.Node) ([]byte, []string, error) {
	result, warnings := convert(config, root)
	return []byte(result), warnings, nil
}

// ---------------------------------------------------------------------------
// General
// ---------------------------------------------------------------------------

func convertGeneral(config map[string]interface{}) string {
	lines := []string{"[General]"}

	lines = append(lines,
		"skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,e.crashlynatics.com",
		"bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32",
	)
	// include-tun is additive in Loon; route-address is not an equivalent
	// replacement for the platform's full routing table.
	tun := clash.MapGetMap(config, "tun")
	if clash.MapGetBool(tun, "enable", false) {
		include := []string{}
		seen := map[string]bool{}
		for _, value := range clash.ToStringSlice(tun["route-address"]) {
			ip, network, err := net.ParseCIDR(value)
			if err != nil || ip.To4() == nil {
				lines = append(lines, "# [WARNING] Loon include-tun requires IPv4 CIDR; skipping "+value)
				continue
			}
			if cidr := network.String(); !seen[cidr] {
				seen[cidr] = true
				include = append(include, cidr)
			}
		}
		if len(include) > 0 {
			lines = append(lines, "# [NOTE] include-tun adds routes to Loon defaults; it does not replace them", "include-tun = "+strings.Join(include, ","))
		}
	}

	dnsCfg, _ := clash.MapGet[map[string]interface{}](config, "dns")

	getStringList := func(key string) []string {
		if dnsCfg == nil {
			return nil
		}
		return clash.ToStringSlice(dnsCfg[key])
	}

	// Plain UDP nameservers
	udpServers := []string{}
	seen := map[string]bool{}
	for _, ns := range getStringList("default-nameserver") {
		ns = strings.Trim(ns, `'"`)
		if !strings.HasPrefix(ns, "https://") && !strings.HasPrefix(ns, "tls://") &&
			!strings.HasPrefix(ns, "quic://") && !strings.HasPrefix(ns, "h3://") {
			if !seen[ns] {
				udpServers = append(udpServers, ns)
				seen[ns] = true
			}
		}
	}
	for _, ns := range getStringList("nameserver") {
		ns = strings.Trim(ns, `'"`)
		if !strings.HasPrefix(ns, "https://") && !strings.HasPrefix(ns, "tls://") &&
			!strings.HasPrefix(ns, "quic://") && !strings.HasPrefix(ns, "h3://") {
			if !seen[ns] {
				udpServers = append(udpServers, ns)
				seen[ns] = true
			}
		}
	}
	if len(udpServers) > 0 {
		lines = append(lines, "dns-server = system,"+strings.Join(udpServers, ","))
	} else {
		lines = append(lines, "dns-server = system")
	}

	// DoH servers
	dohServers := []string{}
	seenDoh := map[string]bool{}
	for _, ns := range getStringList("nameserver") {
		ns = strings.Trim(ns, `'"`)
		if strings.HasPrefix(ns, "https://") && !seenDoh[ns] {
			dohServers = append(dohServers, ns)
			seenDoh[ns] = true
		}
	}
	for _, fb := range getStringList("fallback") {
		fb = strings.Trim(fb, `'"`)
		if strings.HasPrefix(fb, "https://") && !seenDoh[fb] {
			dohServers = append(dohServers, fb)
			seenDoh[fb] = true
		}
	}
	if len(dohServers) > 0 {
		lines = append(lines, "doh-server = "+strings.Join(dohServers, ","))
	}

	// DoQ servers
	doqServers := []string{}
	seenDoq := map[string]bool{}
	for _, src := range [][]string{getStringList("nameserver"), getStringList("fallback")} {
		for _, ns := range src {
			ns = strings.Trim(ns, `'"`)
			if strings.HasPrefix(ns, "quic://") && !seenDoq[ns] {
				doqServers = append(doqServers, ns)
				seenDoq[ns] = true
			}
		}
	}
	if len(doqServers) > 0 {
		lines = append(lines, "doq-server = "+strings.Join(doqServers, ","))
	}

	// DoH3 servers
	doh3Servers := []string{}
	seenDoh3 := map[string]bool{}
	for _, src := range [][]string{getStringList("nameserver"), getStringList("fallback")} {
		for _, ns := range src {
			ns = strings.Trim(ns, `'"`)
			if strings.HasPrefix(ns, "h3://") && !seenDoh3[ns] {
				doh3Servers = append(doh3Servers, ns)
				seenDoh3[ns] = true
			}
		}
	}
	if len(doh3Servers) > 0 {
		lines = append(lines, "doh3-server = "+strings.Join(doh3Servers, ","))
	}

	if dnsCfg != nil {
		if dnsCfg["proxy-server-nameserver"] != nil {
			lines = append(lines, "# [NOTE] proxy-server-nameserver is Clash-specific, no Loon equivalent")
		}
		if dnsCfg["direct-nameserver"] != nil {
			lines = append(lines, "# [NOTE] direct-nameserver is Clash-specific, no Loon equivalent")
		}
	}

	ipv6 := clash.MapGetBool(config, "ipv6", false)
	if dnsCfg != nil && !ipv6 {
		ipv6 = clash.MapGetBool(dnsCfg, "ipv6", false)
	}
	if ipv6 {
		lines = append(lines, "ip-mode = dual")
	} else {
		lines = append(lines, "ip-mode = ipv4-only")
	}

	// Emit allow-wifi-access explicitly in both states so the result does not
	// depend on Loon's own default for LAN access.
	allowLan := clash.MapGetBool(config, "allow-lan", false)
	lines = append(lines,
		"allow-wifi-access = "+clash.BoolStr(allowLan),
		"wifi-access-http-port = 7222",
		"wifi-access-socks5-port = 7221",
	)

	lines = append(lines,
		"proxy-test-url = http://www.gstatic.com/generate_204",
		"internet-test-url = http://wifi.vivo.com.cn/generate_204",
		"test-timeout = 5",
		"resource-parser = https://github.com/sub-store-org/Sub-Store/releases/latest/download/sub-store-parser.loon.min.js",
	)

	// real-ip from fake-ip-filter
	fip := getStringList("fake-ip-filter")
	realIPs := []string{}
	for _, f := range fip {
		f = strings.TrimSpace(f)
		if f != "*" {
			if strings.HasPrefix(f, "+.") {
				f = "*." + strings.TrimPrefix(f, "+.")
			}
			realIPs = append(realIPs, f)
		}
	}
	if len(realIPs) > 0 {
		lines = append(lines, "real-ip = "+strings.Join(realIPs, ","))
	}

	lines = append(lines,
		"hijack-dns = *:53",
		"udp-fallback-mode = REJECT",
		"disable-stun = true",
	)

	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// Proxy converters
// ---------------------------------------------------------------------------

func convertTrojan(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	password := clash.MapGetStr(p, "password", "")
	parts := []string{fmt.Sprintf(`%s = trojan,%s,%d,"%s"`, name, server, port, password)}

	if clash.MapGetBool(p, "skip-cert-verify", false) {
		parts = append(parts, "skip-cert-verify=true")
	}
	if sni := clash.MapGetStr(p, "sni", ""); sni != "" {
		parts = append(parts, "sni="+sni)
	}

	transport := clash.MapGetStr(p, "network", "tcp")
	if transport == "ws" {
		parts = append(parts, "transport=ws")
		wsOpts, _ := clash.MapGet[map[string]interface{}](p, "ws-opts")
		if wsOpts != nil {
			if path := clash.MapGetStr(wsOpts, "path", ""); path != "" {
				parts = append(parts, "path="+path)
			}
			if headers, ok := clash.MapGet[map[string]interface{}](wsOpts, "headers"); ok {
				if host := clash.MapGetStr(headers, "Host", ""); host != "" {
					parts = append(parts, "host="+host)
				}
			}
		}
	} else if transport == "http" {
		parts = append(parts, "transport=http")
		appendHTTPTransportOpts(&parts, p)
	}

	parts = append(parts, "udp="+clash.BoolStr(clash.MapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertSS(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	cipher := clash.MapGetStr(p, "cipher", "aes-256-gcm")
	password := clash.MapGetStr(p, "password", "")
	parts := []string{fmt.Sprintf(`%s = Shadowsocks,%s,%d,%s,"%s"`, name, server, port, cipher, password)}

	plugin := clash.MapGetStr(p, "plugin", "")
	pluginOpts, _ := clash.MapGet[map[string]interface{}](p, "plugin-opts")
	if pluginOpts == nil {
		pluginOpts = map[string]interface{}{}
	}

	switch plugin {
	case "obfs":
		mode := clash.MapGetStr(pluginOpts, "mode", "http")
		parts = append(parts, "obfs-name="+mode)
		if host := clash.MapGetStr(pluginOpts, "host", ""); host != "" {
			parts = append(parts, "obfs-host="+host)
		}
		uri := clash.MapGetStr(pluginOpts, "uri", "")
		if uri == "" {
			uri = clash.MapGetStr(pluginOpts, "path", "")
		}
		if uri != "" {
			parts = append(parts, "obfs-uri="+uri)
		}
	case "shadow-tls":
		if pw := clash.MapGetStr(pluginOpts, "password", ""); pw != "" {
			parts = append(parts, "shadow-tls-password="+pw)
		}
		if host := clash.MapGetStr(pluginOpts, "host", ""); host != "" {
			parts = append(parts, "shadow-tls-sni="+host)
		}
		ver := clash.MapGetInt(pluginOpts, "version", 3)
		parts = append(parts, fmt.Sprintf("shadow-tls-version=%d", ver))
	default:
		if plugin != "" {
			parts = append(parts, "# [WARNING] unsupported SS plugin: "+plugin)
		}
	}

	parts = append(parts, "fast-open="+clash.BoolStr(clash.MapGetBool(p, "tfo", clash.MapGetBool(p, "fast-open", false))))
	parts = append(parts, "udp="+clash.BoolStr(clash.MapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertVmess(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	cipher := clash.MapGetStr(p, "cipher", "auto")
	uuid := clash.MapGetStr(p, "uuid", "")
	parts := []string{fmt.Sprintf(`%s = vmess,%s,%d,%s,"%s"`, name, server, port, cipher, uuid)}

	transport := clash.MapGetStr(p, "network", "tcp")
	parts = append(parts, "transport="+transport)
	parts = append(parts, fmt.Sprintf("alterId=%d", clash.MapGetInt(p, "alterId", 0)))

	switch transport {
	case "ws":
		wsOpts, _ := clash.MapGet[map[string]interface{}](p, "ws-opts")
		if wsOpts != nil {
			if path := clash.MapGetStr(wsOpts, "path", ""); path != "" {
				parts = append(parts, "path="+path)
			}
			if headers, ok := clash.MapGet[map[string]interface{}](wsOpts, "headers"); ok {
				if host := clash.MapGetStr(headers, "Host", ""); host != "" {
					parts = append(parts, "host="+host)
				}
			}
		}
	case "http":
		httpOpts, _ := clash.MapGet[map[string]interface{}](p, "http-opts")
		if httpOpts != nil {
			paths := clash.ToStringSlice(httpOpts["path"])
			if len(paths) > 0 {
				parts = append(parts, "path="+paths[0])
			} else {
				parts = append(parts, "path=/")
			}
			hosts := clash.ToStringSlice(httpOpts["host"])
			if len(hosts) > 0 {
				parts = append(parts, "host="+hosts[0])
			}
		}
	}

	tls := clash.MapGetBool(p, "tls", false) || len(clash.MapGetMap(p, "reality-opts")) > 0
	parts = append(parts, "over-tls="+clash.BoolStr(tls))
	if tls {
		sni := clash.MapGetStr(p, "servername", "")
		if sni == "" {
			sni = clash.MapGetStr(p, "sni", "")
		}
		if sni != "" {
			parts = append(parts, "sni="+sni)
		}
		if clash.MapGetBool(p, "skip-cert-verify", false) {
			parts = append(parts, "skip-cert-verify=true")
		}
	}

	parts = append(parts, "udp="+clash.BoolStr(clash.MapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertVless(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	uuid := clash.MapGetStr(p, "uuid", "")
	parts := []string{fmt.Sprintf(`%s = VLESS,%s,%d,"%s"`, name, server, port, uuid)}

	transport := clash.MapGetStr(p, "network", "tcp")
	parts = append(parts, "transport="+transport)

	if flow := clash.MapGetStr(p, "flow", ""); flow != "" {
		parts = append(parts, "flow="+flow)
	}

	realityOpts, hasReality := clash.MapGet[map[string]interface{}](p, "reality-opts")
	if hasReality && realityOpts != nil {
		if pubKey := clash.MapGetStr(realityOpts, "public-key", ""); pubKey != "" {
			parts = append(parts, fmt.Sprintf(`public-key="%s"`, pubKey))
		}
		if shortID := clash.MapGetStr(realityOpts, "short-id", ""); shortID != "" {
			parts = append(parts, "short-id="+shortID)
		}
	}

	if tlsProfile := loonTLSProfile(clash.MapGetStr(p, "client-fingerprint", "")); tlsProfile != "" {
		parts = append(parts, "tls-profile="+tlsProfile)
	} else if hasReality {
		parts = append(parts, "tls-profile=chrome")
	}

	if transport == "ws" {
		wsOpts, _ := clash.MapGet[map[string]interface{}](p, "ws-opts")
		if wsOpts != nil {
			if path := clash.MapGetStr(wsOpts, "path", ""); path != "" {
				parts = append(parts, "path="+path)
			}
			if headers, ok := clash.MapGet[map[string]interface{}](wsOpts, "headers"); ok {
				if host := clash.MapGetStr(headers, "Host", ""); host != "" {
					parts = append(parts, "host="+host)
				}
			}
		}
	} else if transport == "http" {
		appendHTTPTransportOpts(&parts, p)
	}

	tls := clash.MapGetBool(p, "tls", false) || hasReality
	parts = append(parts, "over-tls="+clash.BoolStr(tls))
	if tls || hasReality {
		sni := clash.MapGetStr(p, "servername", "")
		if sni == "" {
			sni = clash.MapGetStr(p, "sni", "")
		}
		if sni != "" {
			parts = append(parts, "sni="+sni)
		}
		if clash.MapGetBool(p, "skip-cert-verify", false) {
			parts = append(parts, "skip-cert-verify=true")
		}
	}

	parts = append(parts, "udp="+clash.BoolStr(clash.MapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertHysteria2(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	password := clash.MapGetStr(p, "password", "")
	parts := []string{fmt.Sprintf(`%s = Hysteria2,%s,%d,"%s"`, name, server, port, password)}

	if clash.MapGetBool(p, "skip-cert-verify", false) {
		parts = append(parts, "skip-cert-verify=true")
	}
	if sni := clash.MapGetStr(p, "sni", ""); sni != "" {
		parts = append(parts, "sni="+sni)
	}
	if clash.MapGetStr(p, "obfs", "") == "salamander" {
		parts = append(parts, "salamander-password="+loonQuote(clash.MapGetStr(p, "obfs-password", "")))
	}
	if ports := clash.MapGetStr(p, "ports", ""); ports != "" {
		parts = append(parts, "server-ports="+loonQuote(strings.ReplaceAll(ports, "-", ":")))
	}
	if interval := clash.MapGetInt(p, "hop-interval", 0); interval > 0 {
		parts = append(parts, fmt.Sprintf("hop-interval=%d", interval))
	}
	if bandwidth, ok := loonBandwidthMbps(p["down"]); ok {
		parts = append(parts, "download-bandwidth="+bandwidth)
	}
	parts = append(parts, "udp="+clash.BoolStr(clash.MapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertSSR(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	cipher := clash.MapGetStr(p, "cipher", "aes-256-cfb")
	password := clash.MapGetStr(p, "password", "")
	parts := []string{fmt.Sprintf(`%s = ShadowsocksR,%s,%d,%s,"%s"`, name, server, port, cipher, password)}

	protocol := clash.MapGetStr(p, "protocol", "origin")
	parts = append(parts, "protocol="+protocol)
	if pp := clash.MapGetStr(p, "protocol-param", ""); pp != "" {
		parts = append(parts, "protocol-param="+pp)
	}
	obfs := clash.MapGetStr(p, "obfs", "plain")
	parts = append(parts, "obfs="+obfs)
	if op := clash.MapGetStr(p, "obfs-param", ""); op != "" {
		parts = append(parts, "obfs-param="+op)
	}
	parts = append(parts, "fast-open="+clash.BoolStr(clash.MapGetBool(p, "tfo", clash.MapGetBool(p, "fast-open", false))))
	parts = append(parts, "udp="+clash.BoolStr(clash.MapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertSocks5(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	username := clash.MapGetStr(p, "username", "")
	password := clash.MapGetStr(p, "password", "")

	var parts []string
	if username != "" && password != "" {
		parts = []string{fmt.Sprintf(`%s = socks5,%s,%d,"%s","%s"`, name, server, port, username, password)}
	} else if username != "" {
		parts = []string{fmt.Sprintf(`%s = socks5,%s,%d,"%s",""`, name, server, port, username)}
	} else {
		parts = []string{fmt.Sprintf("%s = socks5,%s,%d", name, server, port)}
	}

	if clash.MapGetBool(p, "tls", false) {
		parts = append(parts, "over-tls=true")
		if clash.MapGetBool(p, "skip-cert-verify", false) {
			parts = append(parts, "skip-cert-verify=true")
		}
		if sni := clash.MapGetStr(p, "sni", ""); sni != "" {
			parts = append(parts, "sni="+sni)
		}
	}
	parts = append(parts, "udp="+clash.BoolStr(clash.MapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertHTTP(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	tls := clash.MapGetBool(p, "tls", false)
	proto := "http"
	if tls {
		proto = "https"
	}
	username := clash.MapGetStr(p, "username", "")
	password := clash.MapGetStr(p, "password", "")

	var parts []string
	if username != "" && password != "" {
		parts = []string{fmt.Sprintf(`%s = %s,%s,%d,"%s","%s"`, name, proto, server, port, username, password)}
	} else if username != "" {
		parts = []string{fmt.Sprintf(`%s = %s,%s,%d,"%s",""`, name, proto, server, port, username)}
	} else {
		parts = []string{fmt.Sprintf("%s = %s,%s,%d", name, proto, server, port)}
	}

	if tls {
		if clash.MapGetBool(p, "skip-cert-verify", false) {
			parts = append(parts, "skip-cert-verify=true")
		}
		if sni := clash.MapGetStr(p, "sni", ""); sni != "" {
			parts = append(parts, "sni="+sni)
		}
	}
	return strings.Join(parts, ",")
}

func convertWireGuard(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	privateKey := clash.MapGetStr(p, "private-key", "")
	publicKey := clash.MapGetStr(p, "public-key", "")

	parts := []string{fmt.Sprintf(`%s = WireGuard,interface-ip=%s,private-key="%s"`,
		name, firstString(p["ip"]), privateKey)}
	if ipv6 := firstString(p["ipv6"]); ipv6 != "" {
		parts = append(parts, "interface-ipv6="+ipv6)
	}
	if mtu := clash.MapGetInt(p, "mtu", 0); mtu > 0 {
		parts = append(parts, fmt.Sprintf("mtu=%d", mtu))
	}
	seenDNS4, seenDNS6 := false, false
	for _, dns := range clash.ToStringSlice(p["dns"]) {
		ip := net.ParseIP(dns)
		if ip == nil {
			continue
		}
		if ip.To4() != nil && !seenDNS4 {
			parts = append(parts, "dns="+dns)
			seenDNS4 = true
		} else if ip.To4() == nil && !seenDNS6 {
			parts = append(parts, "dnsv6="+dns)
			seenDNS6 = true
		}
	}
	if keepalive := clash.MapGetInt(p, "persistent-keepalive", clash.MapGetInt(p, "keepalive", -1)); keepalive >= 0 {
		parts = append(parts, fmt.Sprintf("keepalive=%d", keepalive))
	}

	peers := clash.ToMapSlice(p["peers"])
	if len(peers) == 0 {
		peers = []map[string]interface{}{p}
	}
	peerEntries := []string{}
	for _, peerCfg := range peers {
		peer := []string{"public-key=" + loonQuote(clash.MapGetStr(peerCfg, "public-key", publicKey))}
		if psk := clash.MapGetStr(peerCfg, "pre-shared-key", ""); psk != "" {
			peer = append(peer, "preshared-key="+loonQuote(psk))
		}
		if reserved := wireGuardReserved(peerCfg["reserved"]); reserved != "" {
			peer = append(peer, "reserved="+reserved)
		}
		allowedIPs := strings.Join(clash.ToStringSlice(peerCfg["allowed-ips"]), ",")
		if allowedIPs == "" {
			allowedIPs = "0.0.0.0/0"
		}
		peer = append(peer, "allowed-ips="+loonQuote(allowedIPs))
		peerServer := clash.MapGetStr(peerCfg, "server", server)
		peerPort := clash.MapGetInt(peerCfg, "port", port)
		if peerServer != "" && peerPort > 0 {
			peer = append(peer, "endpoint="+net.JoinHostPort(peerServer, fmt.Sprint(peerPort)))
		}
		peerEntries = append(peerEntries, "{"+strings.Join(peer, ",")+"}")
	}
	parts = append(parts, "peers=["+strings.Join(peerEntries, ",")+"]")
	parts = append(parts, "udp="+clash.BoolStr(clash.MapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

// convertAnyTLS renders a Loon AnyTLS node. Loon documents the credential as
// the protocol's required positional argument (AnyTLS,server,port,"password").
// Emitting `password="..."` instead makes Loon treat the whole token, quotes
// included, as the password: the server then silently drops every session
// (log shows `Socket closed by remote peer` right after `[AnyTLS][auth]`), so
// every connection ends in a timeout.
func convertAnyTLS(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	password := clash.MapGetStr(p, "password", "")
	parts := []string{fmt.Sprintf(`%s = AnyTLS,%s,%d,"%s"`, name, server, port, password)}

	if sni := firstNonEmpty(clash.MapGetStr(p, "servername", ""), clash.MapGetStr(p, "sni", "")); sni != "" {
		parts = append(parts, "sni="+sni)
	}
	if clash.MapGetBool(p, "skip-cert-verify", false) {
		parts = append(parts, "skip-cert-verify=true")
	}
	if tlsProfile := loonTLSProfile(clash.MapGetStr(p, "client-fingerprint", "")); tlsProfile != "" {
		parts = append(parts, "tls-profile="+tlsProfile)
	}
	if alpn := strings.Join(clash.ToStringSlice(p["alpn"]), ","); alpn != "" {
		parts = append(parts, fmt.Sprintf(`alpn="%s"`, alpn))
	}
	if reality, ok := clash.MapGet[map[string]interface{}](p, "reality-opts"); ok && reality != nil {
		if pubKey := clash.MapGetStr(reality, "public-key", ""); pubKey != "" {
			parts = append(parts, fmt.Sprintf(`public-key="%s"`, pubKey))
		}
		if shortID := clash.MapGetStr(reality, "short-id", ""); shortID != "" {
			parts = append(parts, "short-id="+shortID)
		}
	}
	if timeout := clash.MapGetInt(p, "idle-session-timeout", 0); timeout > 0 {
		parts = append(parts, fmt.Sprintf("idle-session-timeout=%d", timeout))
	}
	parts = append(parts, "udp="+clash.BoolStr(clash.MapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

// loonTLSProfile maps a Clash client-fingerprint value onto a Loon tls-profile
// value. Loon only documents global, default, safari-ios18, safari-ios-26,
// chrome and chrome147; other Clash values are dropped so Loon falls back to
// its own default ClientHello profile instead of receiving an unknown key.
func loonTLSProfile(fingerprint string) string {
	switch strings.ToLower(strings.TrimSpace(fingerprint)) {
	case "chrome", "chrome147":
		return strings.ToLower(strings.TrimSpace(fingerprint))
	case "safari-ios18", "ios":
		return "safari-ios18"
	case "safari-ios-26":
		return "safari-ios-26"
	case "default", "global":
		return strings.ToLower(strings.TrimSpace(fingerprint))
	}
	return ""
}

func appendHTTPTransportOpts(parts *[]string, p map[string]interface{}) {
	httpOpts, _ := clash.MapGet[map[string]interface{}](p, "http-opts")
	if httpOpts == nil {
		return
	}
	paths := clash.ToStringSlice(httpOpts["path"])
	if len(paths) > 0 {
		*parts = append(*parts, "path="+paths[0])
	}
	hosts := clash.ToStringSlice(httpOpts["host"])
	if len(hosts) > 0 {
		*parts = append(*parts, "host="+hosts[0])
	}
}

func firstString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case []interface{}:
		if len(x) > 0 {
			return strings.TrimSpace(fmt.Sprintf("%v", x[0]))
		}
	case []string:
		if len(x) > 0 {
			return strings.TrimSpace(x[0])
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func wireGuardReserved(v interface{}) string {
	if v == nil {
		return ""
	}
	items := []string{}
	switch x := v.(type) {
	case []interface{}:
		for _, item := range x {
			items = append(items, strings.TrimSpace(fmt.Sprintf("%v", item)))
		}
	case []int:
		for _, item := range x {
			items = append(items, fmt.Sprintf("%d", item))
		}
	case string:
		x = strings.TrimSpace(x)
		if x == "" {
			return ""
		}
		if strings.HasPrefix(x, "[") {
			return x
		}
		if decoded, err := base64.StdEncoding.DecodeString(x); err == nil && len(decoded) == 3 {
			return fmt.Sprintf("[%d,%d,%d]", decoded[0], decoded[1], decoded[2])
		}
		return "[" + x + "]"
	}
	if len(items) == 0 {
		return ""
	}
	return "[" + strings.Join(items, ",") + "]"
}

type proxyConverter func(map[string]interface{}) string

var proxyConverters = map[string]proxyConverter{
	"trojan":    convertTrojan,
	"ss":        convertSS,
	"ssr":       convertSSR,
	"vmess":     convertVmess,
	"vless":     convertVless,
	"hysteria2": convertHysteria2,
	"socks5":    convertSocks5,
	"http":      convertHTTP,
	"wireguard": convertWireGuard,
	"anytls":    convertAnyTLS,
}

func convertProxies(proxies []map[string]interface{}, serverDNS []string) (string, map[string]bool, []string) {
	lines := []string{"[Proxy]"}
	warnings := []string{}
	available := make(map[string]bool, len(proxies))
	for _, p := range proxies {
		ptype := strings.ToLower(clash.MapGetStr(p, "type", ""))
		if conv, ok := proxyConverters[ptype]; ok {
			if reason := loonProxyUnsupportedReason(p); reason != "" {
				warning := fmt.Sprintf("skipping proxy %q: %s", p["name"], reason)
				warnings = append(warnings, warning)
				lines = append(lines, "# [WARNING] "+warning)
				continue
			}
			lines = append(lines, appendLoonNodeOptions(conv(p), p, serverDNS))
			if name := clash.MapGetStr(p, "name", ""); name != "" {
				available[name] = true
			}
		} else {
			lines = append(lines, fmt.Sprintf("# [WARNING] Unsupported proxy type '%s': %s", ptype, clash.MapGetStr(p, "name", "?")))
		}
	}
	return strings.Join(lines, "\n"), available, warnings
}

// ---------------------------------------------------------------------------
// Proxy Chain
// ---------------------------------------------------------------------------

func convertProxyChains(proxies []map[string]interface{}, available map[string]bool) (string, map[string]string) {
	lines := []string{"[Proxy Chain]"}
	chainMap := map[string]string{}
	for _, p := range proxies {
		dialer := clash.MapGetStr(p, "dialer-proxy", "")
		if dialer == "" {
			continue
		}
		name := clash.MapGetStr(p, "name", "")
		if !available[name] {
			continue
		}
		chainName := name + " (Chain)"
		lines = append(lines, fmt.Sprintf("%s = %s,%s,udp=true", chainName, dialer, name))
		chainMap[name] = chainName
	}
	return strings.Join(lines, "\n"), chainMap
}

// ---------------------------------------------------------------------------
// Remote Proxy / Remote Filter
// ---------------------------------------------------------------------------

var proxyURIPrefixes = []string{
	"ss://", "ssr://", "vmess://", "vless://", "trojan://",
	"hysteria://", "hysteria2://", "hy2://", "tuic://",
	"anytls://",
	"socks5://", "http://", "https://",
}

var fullConfigKeys = []string{
	"rules", "proxy-groups", "rule-providers", "listeners",
	"sub-rules", "dns", "tun", "mixed-port", "mode",
}

// checkProxySubscription fetches the URL and returns a warning if the content
// is not a standard proxy subscription. Returns empty string on success.
func checkProxySubscription(rawURL string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return fmt.Sprintf("failed to fetch subscription URL: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Sprintf("subscription URL returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return fmt.Sprintf("failed to read subscription content: %v", err)
	}

	return validateSubscriptionContent(body)
}

func validateSubscriptionContent(body []byte) string {
	content := strings.TrimSpace(string(body))

	decoded, b64Err := base64.StdEncoding.DecodeString(content)
	if b64Err != nil {
		decoded, b64Err = base64.RawStdEncoding.DecodeString(content)
	}
	if b64Err == nil {
		if validLoonTextSubscription(string(decoded)) {
			return ""
		}
	}
	if validLoonTextSubscription(content) {
		return ""
	}

	var yamlMap map[string]interface{}
	if yamlErr := yaml.Unmarshal(body, &yamlMap); yamlErr == nil && yamlMap != nil {
		for _, key := range fullConfigKeys {
			if _, found := yamlMap[key]; found {
				return fmt.Sprintf("subscription returns a full client config (contains '%s' key); provide a standard proxy-only subscription instead", key)
			}
		}
		if _, hasProxies := yamlMap["proxies"]; hasProxies {
			return ""
		}
		return "subscription YAML has no 'proxies' key; provide a standard proxy-only subscription instead"
	}

	return "subscription is not a supported Loon node/URI list, General/Host/Proxy subscription, or proxies-only YAML"
}

func convertRemoteProxy(providers map[string]interface{}, providerOrder []string, serverDNS []string) string {
	lines := []string{"[Remote Proxy]"}
	for _, alias := range providerOrder {
		raw := providers[alias]
		cfg, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		rawURL := clash.MapGetStr(cfg, "url", "")
		if rawURL != "" {
			if warn := checkProxySubscription(rawURL); warn != "" {
				lines = append(lines, fmt.Sprintf("# [WARNING] %s: %s", alias, warn))
			}
		}
		line := fmt.Sprintf("%s = %s,parser-enabled=true,udp=true,enabled=true", alias, rawURL)
		if len(serverDNS) > 0 {
			line += ",server-dns=" + loonQuote(strings.Join(serverDNS, ","))
		}
		lines = append(lines, line)
		if ef := clash.MapGetStr(cfg, "exclude-filter", ""); ef != "" {
			lines = append(lines, fmt.Sprintf("# [NOTE] exclude-filter for %s: %s  (apply via Remote Filter if needed)", alias, ef))
		}
	}
	return strings.Join(lines, "\n")
}

func convertRemoteFilters(groups []map[string]interface{}, providers map[string]interface{}) string {
	lines := []string{"[Remote Filter]"}
	for _, g := range groups {
		uses := clash.ToStringSlice(g["use"])
		if len(uses) == 0 {
			continue
		}
		name := clash.MapGetStr(g, "name", "")
		filt := clash.MapGetStr(g, "filter", "")
		excludeFilt := clash.MapGetStr(g, "exclude-filter", "")
		filterName := name + "_Filter"
		sources := strings.Join(uses, ",")
		if excludeFilt != "" {
			cleanExclude := strings.TrimPrefix(excludeFilt, "(?i)")
			if filt != "" {
				cleanFilt := strings.TrimPrefix(filt, "(?i)")
				lines = append(lines, fmt.Sprintf(`%s = NameRegex,%s,FilterKey = "^(?=.*(?:%s))(?!.*(?i)(%s)).*$"`, filterName, sources, cleanFilt, cleanExclude))
			} else {
				lines = append(lines, fmt.Sprintf(`%s = NameRegex,%s,FilterKey = "^(?i)(?!.*(%s)).*$"`, filterName, sources, cleanExclude))
			}
		} else if filt != "" {
			if strings.HasPrefix(strings.TrimPrefix(filt, "(?i)"), "^") {
				// Already a full regex from Clash; keep as-is.
				lines = append(lines, fmt.Sprintf(`%s = NameRegex,%s,FilterKey = "%s"`, filterName, sources, filt))
			} else {
				// Region-style substring filter: require match and exclude info nodes.
				lines = append(lines, fmt.Sprintf(`%s = NameRegex,%s,FilterKey = "^(?=.*(?:%s))(?!.*(?i)(traffic|expire|剩余|到期|距离下次重置|套餐)).*$"`, filterName, sources, filt))
			}
		} else {
			lines = append(lines, fmt.Sprintf(`%s = NameRegex,%s,FilterKey = "^(?i)(?!.*(traffic|expire|剩余|到期|距离下次重置|套餐)).*$"`, filterName, sources))
		}
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// Proxy Group
// ---------------------------------------------------------------------------

func convertProxyGroups(groups []map[string]interface{}, chainMap map[string]string, available map[string]bool) (string, []string) {
	lines := []string{"[Proxy Group]"}
	var warnings []string

	known := converter.BuiltinPolicies()
	for name := range available {
		known[name] = true
	}
	for name := range converter.ProxyGroupNames(groups) {
		known[name] = true
	}
	// A chain entry only exists when its base proxy was emitted.
	for base, chain := range chainMap {
		if available[base] {
			known[chain] = true
		}
	}

	for _, g := range groups {
		name := clash.MapGetStr(g, "name", "")
		gtype := clash.MapGetStr(g, "type", "select")

		members := []string{}
		for _, px := range clash.ToStringSlice(g["proxies"]) {
			mapped := px
			if cn, ok := chainMap[px]; ok && available[px] {
				mapped = cn
			}
			if !known[mapped] {
				warnings = append(warnings, fmt.Sprintf("proxy group %q references %q, which the Loon output cannot define; skipping", name, px))
				continue
			}
			members = append(members, mapped)
		}
		uses := clash.ToStringSlice(g["use"])
		if len(uses) > 0 {
			members = append(members, name+"_Filter")
		}
		if len(members) == 0 {
			warnings = append(warnings, fmt.Sprintf("proxy group %q has no usable members; falling back to DIRECT", name))
			members = []string{"DIRECT"}
		}

		memberStr := strings.Join(members, ",")

		switch gtype {
		case "select":
			lines = append(lines, fmt.Sprintf("%s = select,%s", name, memberStr))

		case "url-test":
			url := clash.MapGetStr(g, "url", "http://www.gstatic.com/generate_204")
			interval := clash.MapGetInt(g, "interval", 600)
			tolerance := clash.MapGetInt(g, "tolerance", 100)
			lines = append(lines, fmt.Sprintf("%s = url-test,%s,url = %s,interval = %d,tolerance = %d",
				name, memberStr, url, interval, tolerance))

		case "fallback":
			url := clash.MapGetStr(g, "url", "http://www.gstatic.com/generate_204")
			interval := clash.MapGetInt(g, "interval", 600)
			timeout := clash.MapGetInt(g, "timeout", 5000)
			lines = append(lines, fmt.Sprintf("%s = fallback,%s,url = %s,interval = %d,max-timeout = %d",
				name, memberStr, url, interval, timeout))

		case "load-balance":
			url := clash.MapGetStr(g, "url", "http://www.gstatic.com/generate_204")
			interval := clash.MapGetInt(g, "interval", 600)
			strategy := clash.MapGetStr(g, "strategy", "consistent-hashing")
			algoMap := map[string]string{
				"consistent-hashing": "PCC",
				"round-robin":        "Round-Robin",
			}
			algo := algoMap[strategy]
			if algo == "" {
				algo = "PCC"
			}
			timeout := clash.MapGetInt(g, "timeout", 5000)
			lines = append(lines, fmt.Sprintf("%s = load-balance,%s,url = %s,interval = %d,max-timeout = %d,algorithm = %s",
				name, memberStr, url, interval, timeout, algo))

		case "relay":
			lines = append(lines, fmt.Sprintf("# [NOTE] relay group '%s' should be configured in [Proxy Chain] section", name))

		default:
			lines = append(lines, fmt.Sprintf("# [WARNING] Unknown group type '%s': %s", gtype, name))
		}
	}

	return strings.Join(lines, "\n"), warnings
}

// ---------------------------------------------------------------------------
// Rule / Remote Rule
// ---------------------------------------------------------------------------

var reYamlSuffix = regexp.MustCompile(`\.yaml$`)

var (
	reLogicNetwork = regexp.MustCompile(`([(,])\s*NETWORK\s*,`)
	reLogicDstPort = regexp.MustCompile(`([(,])\s*DST-PORT\s*,`)
)

// convertLogicRule rewrites Clash sub-rule types used inside Loon AND/OR/NOT
// rules to their Loon equivalents: NETWORK becomes PROTOCOL and DST-PORT
// becomes DEST-PORT.
func convertLogicRule(rule string) string {
	rule = reLogicNetwork.ReplaceAllString(rule, "${1}PROTOCOL,")
	rule = reLogicDstPort.ReplaceAllString(rule, "${1}DEST-PORT,")
	return rule
}

func convertRuleProviderURL(url string) string {
	if strings.Contains(url, "blackmatrix7") && strings.Contains(url, "rule/Clash/") {
		url = strings.ReplaceAll(url, "rule/Clash/", "rule/Loon/")
		url = reYamlSuffix.ReplaceAllString(url, ".list")
	} else if strings.Contains(url, "ACL4SSR") {
		url = reYamlSuffix.ReplaceAllString(url, ".list")
	}
	return url
}

var unsupportedRuleTypes = map[string]bool{
	"GEOSITE": true, "DOMAIN-REGEX": true,
	"IP-SUFFIX": true, "SRC-IP-SUFFIX": true, "SRC-GEOIP": true,
	"SRC-IP-ASN": true, "SRC-IP-CIDR": true, "IN-PORT": true,
	"IN-TYPE": true, "IN-USER": true, "IN-NAME": true,
	"PROCESS-PATH": true, "PROCESS-PATH-REGEX": true, "PROCESS-PATH-WILDCARD": true,
	// PROCESS-NAME is supported on Loon4Mac 0.3.0(63)+; still ignored on iOS.
	"PROCESS-NAME-REGEX": true, "PROCESS-NAME-WILDCARD": true,
	"UID": true, "DSCP": true, "SUB-RULE": true,
}

func convertRulesAndRemoteRules(rules []interface{}, ruleProviders map[string]interface{}, ruleProviderOrder []string) (string, string) {
	localLines := []string{"[Rule]"}
	remoteLines := []string{"[Remote Rule]"}

	providerURLs := map[string]string{}
	for rpName, rpCfgRaw := range ruleProviders {
		if rpCfg, ok := rpCfgRaw.(map[string]interface{}); ok {
			providerURLs[rpName] = clash.MapGetStr(rpCfg, "url", "")
		}
	}

	seenRemote := map[string]bool{}
	seenLocal := map[string]bool{}
	appendLocal := func(line string) {
		if seenLocal[line] {
			return
		}
		seenLocal[line] = true
		localLines = append(localLines, line)
	}

	for _, ruleRaw := range rules {
		if ruleRaw == nil {
			continue
		}
		ruleStr := strings.TrimSpace(fmt.Sprintf("%v", ruleRaw))
		if ruleStr == "" || strings.HasPrefix(ruleStr, "#") {
			continue
		}

		parts := []string{}
		for _, pt := range strings.Split(ruleStr, ",") {
			parts = append(parts, strings.TrimSpace(pt))
		}
		if len(parts) < 2 {
			continue
		}

		ruleType := strings.ToUpper(parts[0])

		switch ruleType {
		case "RULE-SET":
			rpName := parts[1]
			policy := "PROXY"
			if len(parts) > 2 {
				policy = parts[2]
			}
			rawURL := providerURLs[rpName]
			if rawURL == "" {
				localLines = append(localLines, fmt.Sprintf("# [WARNING] rule-provider '%s' not found", rpName))
				continue
			}
			loonURL := convertRuleProviderURL(rawURL)
			if !seenRemote[rpName] {
				if strings.Contains(rawURL, "ACL4SSR") {
					remoteLines = append(remoteLines, "# [NOTE] ACL4SSR URL — verify Loon compatibility")
				}
				remoteLines = append(remoteLines, fmt.Sprintf("%s,policy=%s,tag=%s,enabled=true", loonURL, policy, rpName))
				seenRemote[rpName] = true
			}

		case "MATCH":
			policy := "DIRECT"
			if len(parts) > 1 {
				policy = parts[1]
			}
			appendLocal("FINAL," + policy)

		case "DST-PORT":
			appendLocal("DEST-PORT," + strings.Join(parts[1:], ","))

		case "GEOIP":
			// Clash supports GEOIP,LAN; Loon does not — expand to private CIDRs.
			if len(parts) >= 2 && strings.EqualFold(parts[1], "LAN") {
				policy := "DIRECT"
				if len(parts) > 2 {
					policy = parts[2]
				}
				for _, cidr := range []string{
					"10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
					"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
				} {
					appendLocal(fmt.Sprintf("IP-CIDR,%s,%s,no-resolve", cidr, policy))
				}
			} else {
				appendLocal(strings.Join(parts, ","))
			}

		case "NETWORK":
			appendLocal("PROTOCOL," + strings.Join(parts[1:], ","))

		case "AND", "OR", "NOT":
			appendLocal(convertLogicRule(ruleStr))

		default:
			if unsupportedRuleTypes[ruleType] {
				localLines = append(localLines, "# [WARNING] Unsupported rule type in Loon: "+strings.Join(parts, ","))
			} else {
				appendLocal(strings.Join(parts, ","))
			}
		}
	}

	return strings.Join(localLines, "\n"), strings.Join(remoteLines, "\n")
}

// ---------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------

func convertHosts(hosts map[string]interface{}, nameserverPolicy map[string]interface{}) string {
	lines := []string{"[Host]"}

	hostNames := make([]string, 0, len(hosts))
	for domain := range hosts {
		hostNames = append(hostNames, domain)
	}
	sort.Strings(hostNames)
	for _, domain := range hostNames {
		lines = append(lines, fmt.Sprintf("%s = %v", domain, hosts[domain]))
	}

	if len(nameserverPolicy) > 0 {
		lines = append(lines, "# --- nameserver-policy ---")
		patterns := make([]string, 0, len(nameserverPolicy))
		for domainPattern := range nameserverPolicy {
			patterns = append(patterns, domainPattern)
		}
		sort.Strings(patterns)
		for _, domainPattern := range patterns {
			pattern := strings.TrimSpace(domainPattern)
			if strings.HasPrefix(pattern, "geosite:") || strings.HasPrefix(pattern, "rule-set:") {
				lines = append(lines, fmt.Sprintf("# [WARNING] pattern not supported in Loon: %s -> %v", pattern, nameserverPolicy[domainPattern]))
				continue
			}
			if strings.HasPrefix(pattern, "+.") {
				pattern = "*." + pattern[2:]
			}
			if pattern == "" {
				continue
			}
			servers := dnsServerList(nameserverPolicy[domainPattern])
			server, ok := firstLoonHostServer(servers)
			if !ok {
				lines = append(lines, fmt.Sprintf("# [WARNING] no Loon-compatible DNS server for %s: %s", pattern, strings.Join(servers, ",")))
				continue
			}
			lines = append(lines, fmt.Sprintf("%s = server:%s", pattern, server))
		}
	}

	return strings.Join(lines, "\n")
}

// dnsServerList normalises a Clash nameserver-policy value, which may be a
// single string or a list of strings, into a slice.
func dnsServerList(v interface{}) []string {
	switch x := v.(type) {
	case string:
		return []string{strings.TrimSpace(x)}
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, item := range x {
			out = append(out, strings.TrimSpace(fmt.Sprintf("%v", item)))
		}
		return out
	case []string:
		out := make([]string, 0, len(x))
		for _, item := range x {
			out = append(out, strings.TrimSpace(item))
		}
		return out
	default:
		if v == nil {
			return nil
		}
		return []string{strings.TrimSpace(fmt.Sprintf("%v", v))}
	}
}

// loonHostServerValue reports whether value can be used after "server:" in
// Loon's [Host] section. Loon accepts an IP address, "system", or an encrypted
// DNS URL; plain "host:port" upstreams are not valid there (Loon reports a
// syntax error and would also need to resolve the upstream first).
func loonHostServerValue(value string) (string, bool) {
	value = strings.TrimSpace(strings.Trim(value, `'"`))
	// Clash nameserver entries may carry options such as "#Fallback".
	if i := strings.IndexByte(value, '#'); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	if value == "" {
		return "", false
	}
	if strings.EqualFold(value, "system") {
		return "system", true
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"https://", "h3://", "quic://"} {
		if strings.HasPrefix(lower, prefix) {
			return value, true
		}
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return strings.Trim(value, "[]"), true
	}
	return "", false
}

func firstLoonHostServer(servers []string) (string, bool) {
	for _, server := range servers {
		if value, ok := loonHostServerValue(server); ok {
			return value, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Main assembly
// ---------------------------------------------------------------------------

func convert(config map[string]interface{}, root *yaml.Node) (string, []string) {
	sections := []string{}
	var warnings []string

	sections = append(sections, convertGeneral(config))

	proxies := clash.ToMapSlice(config["proxies"])
	serverDNS, dnsWarnings := loonServerDNS(config)
	warnings = append(warnings, dnsWarnings...)
	proxyText, available, proxyWarnings := convertProxies(proxies, serverDNS)
	warnings = append(warnings, proxyWarnings...)
	sections = append(sections, proxyText)

	proxyChainText, chainMap := convertProxyChains(proxies, available)
	sections = append(sections, proxyChainText)

	providerOrder := clash.OrderedKeysFromNode(root, "proxy-providers")
	_, providersMap := clash.ToOrderedMap(config["proxy-providers"])
	if providersMap == nil {
		providersMap = map[string]interface{}{}
	}
	if len(providerOrder) == 0 {
		providerOrder, _ = clash.ToOrderedMap(config["proxy-providers"])
	}
	sections = append(sections, convertRemoteProxy(providersMap, providerOrder, serverDNS))

	groups := clash.ToMapSlice(config["proxy-groups"])
	sections = append(sections, convertRemoteFilters(groups, providersMap))

	groupText, groupWarnings := convertProxyGroups(groups, chainMap, available)
	warnings = append(warnings, groupWarnings...)
	sections = append(sections, groupText)

	rules, _ := config["rules"].([]interface{})
	ruleProviderOrder := clash.OrderedKeysFromNode(root, "rule-providers")
	_, ruleProvidersMap := clash.ToOrderedMap(config["rule-providers"])
	if ruleProvidersMap == nil {
		ruleProvidersMap = map[string]interface{}{}
	}
	if len(ruleProviderOrder) == 0 {
		ruleProviderOrder, _ = clash.ToOrderedMap(config["rule-providers"])
	}
	ruleText, remoteRuleText := convertRulesAndRemoteRules(rules, ruleProvidersMap, ruleProviderOrder)
	sections = append(sections, ruleText)
	sections = append(sections, remoteRuleText)

	hostsMap, _ := config["hosts"].(map[string]interface{})
	var nsPolicy map[string]interface{}
	if dnsCfg, ok := config["dns"].(map[string]interface{}); ok {
		nsPolicy, _ = dnsCfg["nameserver-policy"].(map[string]interface{})
	}
	if len(hostsMap) > 0 || len(nsPolicy) > 0 {
		if hostsMap == nil {
			hostsMap = map[string]interface{}{}
		}
		sections = append(sections, convertHosts(hostsMap, nsPolicy))
	}

	sections = append(sections,
		"[Rewrite]",
		"[Remote Rewrite]",
		"[Script]",
		"[Remote Script]",
		"[Plugin]",
		"[MITM]",
	)

	return strings.Join(sections, "\n\n") + "\n", warnings
}
