// Package loon converts a Clash (mihomo) YAML config to a Loon .conf file.
package loon

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

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
func (c *Converter) Convert(config map[string]interface{}, root *yaml.Node) ([]byte, error) {
	result := convert(config, root)
	return []byte(result), nil
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

	if clash.MapGetBool(config, "allow-lan", false) {
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

	parts = append(parts, "fast-open="+clash.BoolStr(clash.MapGetBool(p, "fast-open", false)))
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

	tls := clash.MapGetBool(p, "tls", false)
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
	}

	tls := clash.MapGetBool(p, "tls", false)
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
	parts = append(parts, "fast-open="+clash.BoolStr(clash.MapGetBool(p, "fast-open", false)))
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
		ptype := strings.ToLower(clash.MapGetStr(p, "type", ""))
		if conv, ok := proxyConverters[ptype]; ok {
			lines = append(lines, conv(p))
		} else {
			lines = append(lines, fmt.Sprintf("# [WARNING] Unsupported proxy type '%s': %s", ptype, clash.MapGetStr(p, "name", "?")))
		}
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// Proxy Chain
// ---------------------------------------------------------------------------

func convertProxyChains(proxies []map[string]interface{}) (string, map[string]string) {
	lines := []string{"[Proxy Chain]"}
	chainMap := map[string]string{}
	for _, p := range proxies {
		dialer := clash.MapGetStr(p, "dialer-proxy", "")
		if dialer == "" {
			continue
		}
		name := clash.MapGetStr(p, "name", "")
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

	content := strings.TrimSpace(string(body))

	decoded, b64Err := base64.StdEncoding.DecodeString(content)
	if b64Err != nil {
		decoded, b64Err = base64.RawStdEncoding.DecodeString(content)
	}
	if b64Err == nil {
		lines := strings.Split(strings.TrimSpace(string(decoded)), "\n")
		validCount := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			for _, prefix := range proxyURIPrefixes {
				if strings.HasPrefix(line, prefix) {
					validCount++
					break
				}
			}
		}
		if validCount > 0 {
			return ""
		}
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

	return "subscription content is neither a valid base64 proxy URI list nor a proxies-only YAML"
}

func convertRemoteProxy(providers map[string]interface{}, providerOrder []string) string {
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
		lines = append(lines, fmt.Sprintf("%s = %s", alias, rawURL))
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
// Proxy Group
// ---------------------------------------------------------------------------

func convertProxyGroups(groups []map[string]interface{}, chainMap map[string]string) string {
	lines := []string{"[Proxy Group]"}

	for _, g := range groups {
		name := clash.MapGetStr(g, "name", "")
		gtype := clash.MapGetStr(g, "type", "select")

		members := []string{}
		for _, px := range clash.ToStringSlice(g["proxies"]) {
			if cn, ok := chainMap[px]; ok {
				members = append(members, cn)
			} else {
				members = append(members, px)
			}
		}
		if uses := clash.ToStringSlice(g["use"]); len(uses) > 0 {
			members = append(members, name+"_Filter")
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
// Rule / Remote Rule
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

	providerURLs := map[string]string{}
	for rpName, rpCfgRaw := range ruleProviders {
		if rpCfg, ok := rpCfgRaw.(map[string]interface{}); ok {
			providerURLs[rpName] = clash.MapGetStr(rpCfg, "url", "")
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
// Host
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

	proxies := clash.ToMapSlice(config["proxies"])
	sections = append(sections, convertProxies(proxies))

	proxyChainText, chainMap := convertProxyChains(proxies)
	sections = append(sections, proxyChainText)

	providerOrder := clash.OrderedKeysFromNode(root, "proxy-providers")
	_, providersMap := clash.ToOrderedMap(config["proxy-providers"])
	if providersMap == nil {
		providersMap = map[string]interface{}{}
	}
	if len(providerOrder) == 0 {
		providerOrder, _ = clash.ToOrderedMap(config["proxy-providers"])
	}
	sections = append(sections, convertRemoteProxy(providersMap, providerOrder))

	groups := clash.ToMapSlice(config["proxy-groups"])
	sections = append(sections, convertRemoteFilters(groups, providersMap))

	sections = append(sections, convertProxyGroups(groups, chainMap))

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

	return strings.Join(sections, "\n\n") + "\n"
}
