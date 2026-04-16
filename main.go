// Clash (mihomo) YAML -> Loon .conf converter — Go rewrite of converter.py
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

// AnyMap normalises any YAML mapping to map[string]interface{}.
// yaml.v3 decodes top-level maps into whatever concrete type we pass (&config),
// so nested values come back as map[string]interface{} or as our alias type.
// This function handles both so all callers stay simple.
func anyMap(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	switch m := v.(type) {
	case map[string]interface{}:
		return m
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for k, val := range m {
			out[fmt.Sprintf("%v", k)] = val
		}
		return out
	default:
		return nil
	}
}

func mapGet[T any](m map[string]interface{}, key string) (T, bool) {
	v, ok := m[key]
	if !ok {
		var z T
		return z, false
	}
	t, ok := v.(T)
	return t, ok
}

// mapGetMap retrieves a nested mapping value tolerating both map types.
func mapGetMap(m map[string]interface{}, key string) map[string]interface{} {
	return anyMap(m[key])
}

func mapGetStr(m map[string]interface{}, key string, def string) string {
	v, ok := m[key]
	if !ok {
		return def
	}
	switch s := v.(type) {
	case string:
		return s
	default:
		return fmt.Sprintf("%v", v)
	}
}

func mapGetBool(m map[string]interface{}, key string, def bool) bool {
	v, ok := m[key]
	if !ok {
		return def
	}
	switch b := v.(type) {
	case bool:
		return b
	default:
		return def
	}
}

func mapGetInt(m map[string]interface{}, key string, def int) int {
	v, ok := m[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	default:
		return def
	}
}

func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch s := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(s))
		for _, item := range s {
			out = append(out, strings.TrimSpace(fmt.Sprintf("%v", item)))
		}
		return out
	case []string:
		return s
	default:
		return nil
	}
}

func toMapSlice(v interface{}) []map[string]interface{} {
	if v == nil {
		return nil
	}
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		if m := anyMap(item); m != nil {
			out = append(out, m)
		}
	}
	return out
}

func toOrderedMap(v interface{}) ([]string, map[string]interface{}) {
	// yaml.v3 decodes mappings as map[string]interface{} — key order not preserved.
	// We just return sorted-ish keys.
	m := anyMap(v)
	if m == nil {
		return nil, nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys, m
}

// orderedKeysFromNode extracts the keys of a top-level mapping field in the
// given yaml.Node document, preserving the original YAML document order.
func orderedKeysFromNode(root *yaml.Node, field string) []string {
	if root == nil {
		return nil
	}
	doc := root
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		doc = doc.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == field {
			node := doc.Content[i+1]
			if node.Kind == yaml.MappingNode {
				keys := make([]string, 0, len(node.Content)/2)
				for j := 0; j+1 < len(node.Content); j += 2 {
					keys = append(keys, node.Content[j].Value)
				}
				return keys
			}
		}
	}
	return nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ---------------------------------------------------------------------------
// Unit 2: [General]
// ---------------------------------------------------------------------------

func convertGeneral(config map[string]interface{}) string {
	lines := []string{"[General]"}

	lines = append(lines,
		"skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,e.crashlynatics.com",
		"bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32",
	)

	dnsCfgRaw, _ := mapGet[map[string]interface{}](config, "dns")
	dnsCfg := dnsCfgRaw // may be nil

	getString := func(key, def string) string {
		if dnsCfg == nil {
			return def
		}
		return mapGetStr(dnsCfg, key, def)
	}
	_ = getString

	getStringList := func(key string) []string {
		if dnsCfg == nil {
			return nil
		}
		return toStringSlice(dnsCfg[key])
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

	// Notes for Clash-specific DNS options
	if dnsCfg != nil {
		if v := dnsCfg["proxy-server-nameserver"]; v != nil {
			lines = append(lines, "# [NOTE] proxy-server-nameserver is Clash-specific, no Loon equivalent")
		}
		if v := dnsCfg["direct-nameserver"]; v != nil {
			lines = append(lines, "# [NOTE] direct-nameserver is Clash-specific, no Loon equivalent")
		}
	}

	// ip-mode
	ipv6 := mapGetBool(config, "ipv6", false)
	if dnsCfg != nil && !ipv6 {
		ipv6 = mapGetBool(dnsCfg, "ipv6", false)
	}
	if ipv6 {
		lines = append(lines, "ip-mode = dual")
	} else {
		lines = append(lines, "ip-mode = ipv4-only")
	}

	// allow-wifi-access
	if mapGetBool(config, "allow-lan", false) {
		lines = append(lines,
			"allow-wifi-access = true",
			"wifi-access-http-port = 7222",
			"wifi-access-socks5-port = 7221",
		)
	}

	lines = append(lines,
		"proxy-test-url = http://www.gstatic.com/generate_204",
		"internet-test-url = http://wifi.vivo.com.cn/generate_204",
		"test-timeout = 5",
		"resource-parser = https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/backend/dist/sub-store-parser.loon.min.js",
	)

	// real-ip from fake-ip-filter
	fip := getStringList("fake-ip-filter")
	realIPs := []string{}
	for _, f := range fip {
		f = strings.TrimSpace(f)
		if f != "*" {
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
// Unit 3: [Proxy]
// ---------------------------------------------------------------------------

func convertTrojan(p map[string]interface{}) string {
	name := mapGetStr(p, "name", "")
	server := mapGetStr(p, "server", "")
	port := mapGetInt(p, "port", 0)
	password := mapGetStr(p, "password", "")
	parts := []string{fmt.Sprintf(`%s = trojan,%s,%d,"%s"`, name, server, port, password)}

	if mapGetBool(p, "skip-cert-verify", false) {
		parts = append(parts, "skip-cert-verify=true")
	}
	if sni := mapGetStr(p, "sni", ""); sni != "" {
		parts = append(parts, "sni="+sni)
	}

	transport := mapGetStr(p, "network", "tcp")
	if transport == "ws" {
		parts = append(parts, "transport=ws")
		wsOpts, _ := mapGet[map[string]interface{}](p, "ws-opts")
		if wsOpts != nil {
			if path := mapGetStr(wsOpts, "path", ""); path != "" {
				parts = append(parts, "path="+path)
			}
			if headers, ok := mapGet[map[string]interface{}](wsOpts, "headers"); ok {
				if host := mapGetStr(headers, "Host", ""); host != "" {
					parts = append(parts, "host="+host)
				}
			}
		}
	}

	udp := mapGetBool(p, "udp", true)
	parts = append(parts, "udp="+boolStr(udp))
	return strings.Join(parts, ",")
}

func convertSS(p map[string]interface{}) string {
	name := mapGetStr(p, "name", "")
	server := mapGetStr(p, "server", "")
	port := mapGetInt(p, "port", 0)
	cipher := mapGetStr(p, "cipher", "aes-256-gcm")
	password := mapGetStr(p, "password", "")
	parts := []string{fmt.Sprintf(`%s = Shadowsocks,%s,%d,%s,"%s"`, name, server, port, cipher, password)}

	plugin := mapGetStr(p, "plugin", "")
	pluginOpts, _ := mapGet[map[string]interface{}](p, "plugin-opts")
	if pluginOpts == nil {
		pluginOpts = map[string]interface{}{}
	}

	switch plugin {
	case "obfs":
		mode := mapGetStr(pluginOpts, "mode", "http")
		parts = append(parts, "obfs-name="+mode)
		if host := mapGetStr(pluginOpts, "host", ""); host != "" {
			parts = append(parts, "obfs-host="+host)
		}
		uri := mapGetStr(pluginOpts, "uri", "")
		if uri == "" {
			uri = mapGetStr(pluginOpts, "path", "")
		}
		if uri != "" {
			parts = append(parts, "obfs-uri="+uri)
		}
	case "shadow-tls":
		if pw := mapGetStr(pluginOpts, "password", ""); pw != "" {
			parts = append(parts, "shadow-tls-password="+pw)
		}
		if host := mapGetStr(pluginOpts, "host", ""); host != "" {
			parts = append(parts, "shadow-tls-sni="+host)
		}
		ver := mapGetInt(pluginOpts, "version", 3)
		parts = append(parts, fmt.Sprintf("shadow-tls-version=%d", ver))
	default:
		if plugin != "" {
			parts = append(parts, "# [WARNING] unsupported SS plugin: "+plugin)
		}
	}

	parts = append(parts, "fast-open="+boolStr(mapGetBool(p, "fast-open", false)))
	parts = append(parts, "udp="+boolStr(mapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertVmess(p map[string]interface{}) string {
	name := mapGetStr(p, "name", "")
	server := mapGetStr(p, "server", "")
	port := mapGetInt(p, "port", 0)
	cipher := mapGetStr(p, "cipher", "auto")
	uuid := mapGetStr(p, "uuid", "")
	parts := []string{fmt.Sprintf(`%s = vmess,%s,%d,%s,"%s"`, name, server, port, cipher, uuid)}

	transport := mapGetStr(p, "network", "tcp")
	parts = append(parts, "transport="+transport)
	parts = append(parts, fmt.Sprintf("alterId=%d", mapGetInt(p, "alterId", 0)))

	switch transport {
	case "ws":
		wsOpts, _ := mapGet[map[string]interface{}](p, "ws-opts")
		if wsOpts != nil {
			if path := mapGetStr(wsOpts, "path", ""); path != "" {
				parts = append(parts, "path="+path)
			}
			if headers, ok := mapGet[map[string]interface{}](wsOpts, "headers"); ok {
				if host := mapGetStr(headers, "Host", ""); host != "" {
					parts = append(parts, "host="+host)
				}
			}
		}
	case "http":
		httpOpts, _ := mapGet[map[string]interface{}](p, "http-opts")
		if httpOpts != nil {
			paths := toStringSlice(httpOpts["path"])
			if len(paths) > 0 {
				parts = append(parts, "path="+paths[0])
			} else {
				parts = append(parts, "path=/")
			}
			hosts := toStringSlice(httpOpts["host"])
			if len(hosts) > 0 {
				parts = append(parts, "host="+hosts[0])
			}
		}
	}

	tls := mapGetBool(p, "tls", false)
	parts = append(parts, "over-tls="+boolStr(tls))
	if tls {
		sni := mapGetStr(p, "servername", "")
		if sni == "" {
			sni = mapGetStr(p, "sni", "")
		}
		if sni != "" {
			parts = append(parts, "sni="+sni)
		}
		if mapGetBool(p, "skip-cert-verify", false) {
			parts = append(parts, "skip-cert-verify=true")
		}
	}

	parts = append(parts, "udp="+boolStr(mapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertVless(p map[string]interface{}) string {
	name := mapGetStr(p, "name", "")
	server := mapGetStr(p, "server", "")
	port := mapGetInt(p, "port", 0)
	uuid := mapGetStr(p, "uuid", "")
	parts := []string{fmt.Sprintf(`%s = VLESS,%s,%d,"%s"`, name, server, port, uuid)}

	transport := mapGetStr(p, "network", "tcp")
	parts = append(parts, "transport="+transport)

	if flow := mapGetStr(p, "flow", ""); flow != "" {
		parts = append(parts, "flow="+flow)
	}

	realityOpts, hasReality := mapGet[map[string]interface{}](p, "reality-opts")
	if hasReality && realityOpts != nil {
		if pubKey := mapGetStr(realityOpts, "public-key", ""); pubKey != "" {
			parts = append(parts, fmt.Sprintf(`public-key="%s"`, pubKey))
		}
		if shortID := mapGetStr(realityOpts, "short-id", ""); shortID != "" {
			parts = append(parts, "short-id="+shortID)
		}
	}

	if transport == "ws" {
		wsOpts, _ := mapGet[map[string]interface{}](p, "ws-opts")
		if wsOpts != nil {
			if path := mapGetStr(wsOpts, "path", ""); path != "" {
				parts = append(parts, "path="+path)
			}
			if headers, ok := mapGet[map[string]interface{}](wsOpts, "headers"); ok {
				if host := mapGetStr(headers, "Host", ""); host != "" {
					parts = append(parts, "host="+host)
				}
			}
		}
	}

	tls := mapGetBool(p, "tls", false)
	parts = append(parts, "over-tls="+boolStr(tls))
	if tls || hasReality {
		sni := mapGetStr(p, "servername", "")
		if sni == "" {
			sni = mapGetStr(p, "sni", "")
		}
		if sni != "" {
			parts = append(parts, "sni="+sni)
		}
		if mapGetBool(p, "skip-cert-verify", false) {
			parts = append(parts, "skip-cert-verify=true")
		}
	}

	parts = append(parts, "udp="+boolStr(mapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertHysteria2(p map[string]interface{}) string {
	name := mapGetStr(p, "name", "")
	server := mapGetStr(p, "server", "")
	port := mapGetInt(p, "port", 0)
	password := mapGetStr(p, "password", "")
	parts := []string{fmt.Sprintf(`%s = Hysteria2,%s,%d,"%s"`, name, server, port, password)}

	if mapGetBool(p, "skip-cert-verify", false) {
		parts = append(parts, "skip-cert-verify=true")
	}
	if sni := mapGetStr(p, "sni", ""); sni != "" {
		parts = append(parts, "sni="+sni)
	}
	parts = append(parts, "udp="+boolStr(mapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertSSR(p map[string]interface{}) string {
	name := mapGetStr(p, "name", "")
	server := mapGetStr(p, "server", "")
	port := mapGetInt(p, "port", 0)
	cipher := mapGetStr(p, "cipher", "aes-256-cfb")
	password := mapGetStr(p, "password", "")
	parts := []string{fmt.Sprintf(`%s = ShadowsocksR,%s,%d,%s,"%s"`, name, server, port, cipher, password)}

	protocol := mapGetStr(p, "protocol", "origin")
	parts = append(parts, "protocol="+protocol)
	if pp := mapGetStr(p, "protocol-param", ""); pp != "" {
		parts = append(parts, "protocol-param="+pp)
	}
	obfs := mapGetStr(p, "obfs", "plain")
	parts = append(parts, "obfs="+obfs)
	if op := mapGetStr(p, "obfs-param", ""); op != "" {
		parts = append(parts, "obfs-param="+op)
	}
	parts = append(parts, "fast-open="+boolStr(mapGetBool(p, "fast-open", false)))
	parts = append(parts, "udp="+boolStr(mapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertSocks5(p map[string]interface{}) string {
	name := mapGetStr(p, "name", "")
	server := mapGetStr(p, "server", "")
	port := mapGetInt(p, "port", 0)
	username := mapGetStr(p, "username", "")
	password := mapGetStr(p, "password", "")

	var parts []string
	if username != "" && password != "" {
		parts = []string{fmt.Sprintf(`%s = socks5,%s,%d,"%s","%s"`, name, server, port, username, password)}
	} else if username != "" {
		parts = []string{fmt.Sprintf(`%s = socks5,%s,%d,"%s",""`, name, server, port, username)}
	} else {
		parts = []string{fmt.Sprintf("%s = socks5,%s,%d", name, server, port)}
	}

	if mapGetBool(p, "tls", false) {
		if mapGetBool(p, "skip-cert-verify", false) {
			parts = append(parts, "skip-cert-verify=true")
		}
		if sni := mapGetStr(p, "sni", ""); sni != "" {
			parts = append(parts, "sni="+sni)
		}
	}
	parts = append(parts, "udp="+boolStr(mapGetBool(p, "udp", true)))
	return strings.Join(parts, ",")
}

func convertHTTP(p map[string]interface{}) string {
	name := mapGetStr(p, "name", "")
	server := mapGetStr(p, "server", "")
	port := mapGetInt(p, "port", 0)
	tls := mapGetBool(p, "tls", false)
	proto := "http"
	if tls {
		proto = "https"
	}
	username := mapGetStr(p, "username", "")
	password := mapGetStr(p, "password", "")

	var parts []string
	if username != "" && password != "" {
		parts = []string{fmt.Sprintf(`%s = %s,%s,%d,"%s","%s"`, name, proto, server, port, username, password)}
	} else if username != "" {
		parts = []string{fmt.Sprintf(`%s = %s,%s,%d,"%s",""`, name, proto, server, port, username)}
	} else {
		parts = []string{fmt.Sprintf("%s = %s,%s,%d", name, proto, server, port)}
	}

	if tls {
		if mapGetBool(p, "skip-cert-verify", false) {
			parts = append(parts, "skip-cert-verify=true")
		}
		if sni := mapGetStr(p, "sni", ""); sni != "" {
			parts = append(parts, "sni="+sni)
		}
	}
	return strings.Join(parts, ",")
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
}

func convertProxies(proxies []map[string]interface{}) string {
	lines := []string{"[Proxy]"}
	for _, p := range proxies {
		ptype := strings.ToLower(mapGetStr(p, "type", ""))
		if conv, ok := proxyConverters[ptype]; ok {
			lines = append(lines, conv(p))
		} else {
			lines = append(lines, fmt.Sprintf("# [WARNING] Unsupported proxy type '%s': %s", ptype, mapGetStr(p, "name", "?")))
		}
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// Unit 3b: [Proxy Chain]
// ---------------------------------------------------------------------------

func convertProxyChains(proxies []map[string]interface{}) (string, map[string]string) {
	lines := []string{"[Proxy Chain]"}
	chainMap := map[string]string{}
	for _, p := range proxies {
		dialer := mapGetStr(p, "dialer-proxy", "")
		if dialer == "" {
			continue
		}
		name := mapGetStr(p, "name", "")
		chainName := name + " (Chain)"
		// In Loon Proxy Chain the proxies are listed first-hop to last-hop.
		// Clash dialer-proxy means the named proxy's TCP connection goes out
		// through the dialer, so the actual path is: client → dialer → proxy
		// server → destination.  List dialer first, then the proxy node.
		lines = append(lines, fmt.Sprintf("%s = %s,%s,udp=true", chainName, dialer, name))
		chainMap[name] = chainName
	}
	return strings.Join(lines, "\n"), chainMap
}

// ---------------------------------------------------------------------------
// Unit 4: [Remote Proxy] + [Remote Filter]
// ---------------------------------------------------------------------------

func convertRemoteProxy(providers map[string]interface{}, providerOrder []string) string {
	lines := []string{"[Remote Proxy]"}
	for _, alias := range providerOrder {
		raw := providers[alias]
		cfg, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		url := mapGetStr(cfg, "url", "")
		lines = append(lines, fmt.Sprintf("%s = %s", alias, url))
		if ef := mapGetStr(cfg, "exclude-filter", ""); ef != "" {
			lines = append(lines, fmt.Sprintf("# [NOTE] exclude-filter for %s: %s  (apply via Remote Filter if needed)", alias, ef))
		}
	}
	return strings.Join(lines, "\n")
}

func convertRemoteFilters(groups []map[string]interface{}, providers map[string]interface{}) string {
	lines := []string{"[Remote Filter]"}
	for _, g := range groups {
		uses := toStringSlice(g["use"])
		if len(uses) == 0 {
			continue
		}
		name := mapGetStr(g, "name", "")
		filt := mapGetStr(g, "filter", "")
		filterName := name + "_Filter"
		sources := strings.Join(uses, ",")
		if filt != "" {
			lines = append(lines, fmt.Sprintf(`%s = NameRegex,%s,FilterKey = "%s"`, filterName, sources, filt))
		} else {
			lines = append(lines, fmt.Sprintf(`%s = NameRegex,%s,FilterKey = "^(?i)(?!.*(traffic|expire|剩余|到期)).*$"`, filterName, sources))
		}
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// Unit 5: [Proxy Group]
// ---------------------------------------------------------------------------

func convertProxyGroups(groups []map[string]interface{}, chainMap map[string]string) string {
	lines := []string{"[Proxy Group]"}

	for _, g := range groups {
		name := mapGetStr(g, "name", "")
		gtype := mapGetStr(g, "type", "select")

		members := []string{}
		for _, px := range toStringSlice(g["proxies"]) {
			if cn, ok := chainMap[px]; ok {
				members = append(members, cn)
			} else {
				members = append(members, px)
			}
		}
		if uses := toStringSlice(g["use"]); len(uses) > 0 {
			members = append(members, name+"_Filter")
		}

		memberStr := strings.Join(members, ",")

		switch gtype {
		case "select":
			lines = append(lines, fmt.Sprintf("%s = select,%s", name, memberStr))

		case "url-test":
			url := mapGetStr(g, "url", "http://www.gstatic.com/generate_204")
			interval := mapGetInt(g, "interval", 600)
			tolerance := mapGetInt(g, "tolerance", 100)
			lines = append(lines, fmt.Sprintf("%s = url-test,%s,url = %s,interval = %d,tolerance = %d",
				name, memberStr, url, interval, tolerance))

		case "fallback":
			url := mapGetStr(g, "url", "http://www.gstatic.com/generate_204")
			interval := mapGetInt(g, "interval", 600)
			timeout := mapGetInt(g, "timeout", 5000)
			lines = append(lines, fmt.Sprintf("%s = fallback,%s,url = %s,interval = %d,max-timeout = %d",
				name, memberStr, url, interval, timeout))

		case "load-balance":
			url := mapGetStr(g, "url", "http://www.gstatic.com/generate_204")
			interval := mapGetInt(g, "interval", 600)
			strategy := mapGetStr(g, "strategy", "consistent-hashing")
			algoMap := map[string]string{
				"consistent-hashing": "pcc",
				"round-robin":        "Round-Robin",
			}
			algo := algoMap[strategy]
			if algo == "" {
				algo = "pcc"
			}
			lines = append(lines, fmt.Sprintf("%s = load-balance,%s,url = %s,interval = %d,algorithm = %s",
				name, memberStr, url, interval, algo))

		case "relay":
			lines = append(lines, fmt.Sprintf("# [NOTE] relay group '%s' should be configured in [Proxy Chain] section", name))

		default:
			lines = append(lines, fmt.Sprintf("# [WARNING] Unknown group type '%s': %s", gtype, name))
		}
	}

	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// Unit 6: [Rule] + [Remote Rule]
// ---------------------------------------------------------------------------

var reYamlSuffix = regexp.MustCompile(`\.yaml$`)

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
	"GEOSITE": true, "DOMAIN-REGEX": true, "DOMAIN-WILDCARD": true,
	"IP-SUFFIX": true, "SRC-IP-SUFFIX": true, "SRC-GEOIP": true,
	"SRC-IP-ASN": true, "SRC-IP-CIDR": true, "IN-PORT": true,
	"IN-TYPE": true, "IN-USER": true, "IN-NAME": true,
	"PROCESS-PATH": true, "PROCESS-PATH-REGEX": true, "PROCESS-PATH-WILDCARD": true,
	"PROCESS-NAME": true, "PROCESS-NAME-REGEX": true, "PROCESS-NAME-WILDCARD": true,
	"UID": true, "DSCP": true, "NETWORK": true, "SUB-RULE": true,
	"AND": true, "OR": true, "NOT": true,
}

func convertRulesAndRemoteRules(rules []interface{}, ruleProviders map[string]interface{}, ruleProviderOrder []string) (string, string) {
	localLines := []string{"[Rule]"}
	remoteLines := []string{"[Remote Rule]"}

	// Build provider URL map
	providerURLs := map[string]string{}
	for rpName, rpCfgRaw := range ruleProviders {
		if rpCfg, ok := rpCfgRaw.(map[string]interface{}); ok {
			providerURLs[rpName] = mapGetStr(rpCfg, "url", "")
		}
	}

	seenRemote := map[string]bool{}

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
			localLines = append(localLines, "FINAL,"+policy)

		case "DST-PORT":
			localLines = append(localLines, "DEST-PORT,"+strings.Join(parts[1:], ","))

		default:
			if unsupportedRuleTypes[ruleType] {
				localLines = append(localLines, "# [WARNING] Unsupported rule type in Loon: "+strings.Join(parts, ","))
			} else {
				localLines = append(localLines, strings.Join(parts, ","))
			}
		}
	}

	return strings.Join(localLines, "\n"), strings.Join(remoteLines, "\n")
}

// ---------------------------------------------------------------------------
// Unit 7: [Host]
// ---------------------------------------------------------------------------

func convertHosts(hosts map[string]interface{}, nameserverPolicy map[string]interface{}) string {
	lines := []string{"[Host]"}

	for domain, target := range hosts {
		lines = append(lines, fmt.Sprintf("%s = %v", domain, target))
	}

	if len(nameserverPolicy) > 0 {
		lines = append(lines, "# --- nameserver-policy ---")
		for domainPattern, dnsServerRaw := range nameserverPolicy {
			pattern := strings.TrimSpace(domainPattern)
			if strings.HasPrefix(pattern, "geosite:") || strings.HasPrefix(pattern, "rule-set:") {
				lines = append(lines, fmt.Sprintf("# [WARNING] pattern not supported in Loon: %s -> %v", pattern, dnsServerRaw))
				continue
			}
			if strings.HasPrefix(pattern, "+.") {
				pattern = "*." + pattern[2:]
			}
			var server string
			switch v := dnsServerRaw.(type) {
			case []interface{}:
				if len(v) > 0 {
					server = strings.TrimSpace(fmt.Sprintf("%v", v[0]))
				}
			default:
				server = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
			lines = append(lines, fmt.Sprintf("%s = server:%s", pattern, server))
		}
	}

	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// Main assembly
// ---------------------------------------------------------------------------

func convert(config map[string]interface{}, root *yaml.Node) string {
	sections := []string{}

	sections = append(sections, convertGeneral(config))

	proxies := toMapSlice(config["proxies"])
	sections = append(sections, convertProxies(proxies))

	proxyChainText, chainMap := convertProxyChains(proxies)
	sections = append(sections, proxyChainText)

	// proxy-providers — preserve insertion order via yaml.Node
	providerOrder := orderedKeysFromNode(root, "proxy-providers")
	_, providersMap := toOrderedMap(config["proxy-providers"])
	if providersMap == nil {
		providersMap = map[string]interface{}{}
	}
	if len(providerOrder) == 0 {
		providerOrder, _ = toOrderedMap(config["proxy-providers"])
	}
	sections = append(sections, convertRemoteProxy(providersMap, providerOrder))

	groups := toMapSlice(config["proxy-groups"])
	sections = append(sections, convertRemoteFilters(groups, providersMap))

	sections = append(sections, convertProxyGroups(groups, chainMap))

	rules, _ := config["rules"].([]interface{})
	ruleProviderOrder := orderedKeysFromNode(root, "rule-providers")
	_, ruleProvidersMap := toOrderedMap(config["rule-providers"])
	if ruleProvidersMap == nil {
		ruleProvidersMap = map[string]interface{}{}
	}
	if len(ruleProviderOrder) == 0 {
		ruleProviderOrder, _ = toOrderedMap(config["rule-providers"])
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

	return strings.Join(sections, "\n\n") + "\n"
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	const defaultOutputPath = "output/loon.conf"

	inputFlag := flag.String("input", "", "Path to Clash YAML config file")
	outputFlag := flag.String("o", defaultOutputPath, "Output Loon config file path")
	flag.Usage = func() {
		cmd := filepath.Base(os.Args[0])
		fmt.Fprintf(os.Stderr, "Convert Clash (mihomo) YAML config into a Loon .conf file.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options] [input_file]\n\n", cmd)
		fmt.Fprintf(os.Stderr, "Input selection:\n")
		fmt.Fprintf(os.Stderr, "  1. Use -input when provided\n")
		fmt.Fprintf(os.Stderr, "  2. Otherwise use positional [input_file]\n")
		fmt.Fprintf(os.Stderr, "  3. Input is required\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nDefaults:\n")
		fmt.Fprintf(os.Stderr, "  output %s\n\n", defaultOutputPath)
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s input/clash.yaml\n", cmd)
		fmt.Fprintf(os.Stderr, "  %s -input input/clash.yaml -o output/custom.conf\n\n", cmd)
		fmt.Fprintf(os.Stderr, "Output:\n")
		fmt.Fprintf(os.Stderr, "  Creates parent directories for the output file when needed.\n")
		fmt.Fprintf(os.Stderr, "  Prints a single conversion summary line after success.\n")
	}
	flag.Parse()

	inputPath := *inputFlag
	if inputPath == "" && flag.NArg() > 0 {
		inputPath = flag.Arg(0)
	}
	if inputPath == "" {
		flag.Usage()
		os.Exit(0)
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot read file: %s\n", err)
		os.Exit(1)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid YAML: %s\n", err)
		os.Exit(1)
	}
	if config == nil {
		fmt.Fprintf(os.Stderr, "Warning: empty or invalid YAML, generating skeleton config\n")
		config = map[string]interface{}{}
	}

	var rootNode yaml.Node
	_ = yaml.Unmarshal(data, &rootNode)

	result := convert(config, &rootNode)

	outPath := *outputFlag
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot create output directory: %s\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, []byte(result), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot write output: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Converted: %s -> %s\n", inputPath, outPath)
}
