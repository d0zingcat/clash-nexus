// Package qx converts a Clash (mihomo) YAML config to a Quantumult X .conf file.
package qx

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"clash-nexus/converter/clash"
)

// Converter converts Clash YAML to Quantumult X .conf format.
type Converter struct{}

// New returns a new QX Converter.
func New() *Converter { return &Converter{} }

// Name returns the short identifier for this converter.
func (c *Converter) Name() string { return "qx" }

// DefaultExtension returns the file extension for QX configs.
func (c *Converter) DefaultExtension() string { return ".conf" }

// Convert transforms a Clash config map into a Quantumult X .conf byte slice.
func (c *Converter) Convert(config map[string]interface{}, root *yaml.Node) ([]byte, []string, error) {
	result, warnings := convert(config, root)
	return []byte(result), warnings, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type proxyConverter func(map[string]interface{}) string

var resolveHostIPs = func(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP != nil {
			ips = append(ips, addr.IP)
		}
	}
	return ips, nil
}

// lowerPolicy maps Clash built-in policy names to QX lowercase equivalents.
func lowerPolicy(p string) string {
	switch strings.ToUpper(p) {
	case "DIRECT":
		return "direct"
	case "REJECT", "REJECT-DROP", "REJECT-TINYGIF":
		return "reject"
	case "PROXY":
		return "proxy"
	}
	return p
}

var reYamlSuffix = regexp.MustCompile(`\.yaml$`)

// convertRuleProviderURL converts blackmatrix7 rule URLs to the QuantumultX path.
// Handles both rule/Clash/ and rule/Loon/ input paths.
func convertRuleProviderURL(url string) string {
	if strings.Contains(url, "blackmatrix7") {
		url = strings.ReplaceAll(url, "rule/Clash/", "rule/QuantumultX/")
		url = strings.ReplaceAll(url, "rule/Loon/", "rule/QuantumultX/")
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
	"PROCESS-NAME": true, "PROCESS-NAME-REGEX": true, "PROCESS-NAME-WILDCARD": true,
	"UID": true, "DSCP": true, "NETWORK": true, "SUB-RULE": true,
	"AND": true, "OR": true, "NOT": true,
}

// buildChainInfo extracts proxy-chain metadata from proxies and groups.
//
//	chainProxies:     proxyName → dialerGroupName
//	proxyChainGroups: groupName → true when a direct member proxy has dialer-proxy
func buildChainInfo(proxies []map[string]interface{}, groups []map[string]interface{}) (
	chainProxies map[string]string,
	proxyChainGroups map[string]bool,
) {
	chainProxies = map[string]string{}
	proxyChainGroups = map[string]bool{}

	for _, p := range proxies {
		if dialer := clash.MapGetStr(p, "dialer-proxy", ""); dialer != "" {
			chainProxies[clash.MapGetStr(p, "name", "")] = dialer
		}
	}

	for _, g := range groups {
		name := clash.MapGetStr(g, "name", "")
		for _, px := range clash.ToStringSlice(g["proxies"]) {
			if _, ok := chainProxies[px]; ok {
				proxyChainGroups[name] = true
				break
			}
		}
	}

	return
}

func chainServerIPRoutes(proxies []map[string]interface{}) ([]string, []string) {
	var routes []string
	var warnings []string
	seenRoute := map[string]bool{}

	for _, p := range proxies {
		dialer := clash.MapGetStr(p, "dialer-proxy", "")
		if dialer == "" {
			continue
		}
		server := strings.TrimSpace(clash.MapGetStr(p, "server", ""))
		if server == "" {
			continue
		}

		ips, err := serverIPs(server)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cannot resolve dialer-proxy server %q: %s", server, err))
			continue
		}
		if len(ips) == 0 {
			warnings = append(warnings, fmt.Sprintf("cannot resolve dialer-proxy server %q: no IP addresses", server))
			continue
		}

		for _, ip := range ips {
			ruleType, cidr := ipCIDRRule(ip)
			if cidr == "" {
				continue
			}
			key := cidr + "\x00" + dialer
			if seenRoute[key] {
				continue
			}
			seenRoute[key] = true
			routes = append(routes, fmt.Sprintf("%s, %s, %s", ruleType, cidr, lowerPolicy(dialer)))
		}
	}

	return routes, warnings
}

func serverIPs(server string) ([]net.IP, error) {
	if ip := net.ParseIP(strings.Trim(server, "[]")); ip != nil {
		return []net.IP{ip}, nil
	}
	return resolveHostIPs(server)
}

func ipCIDRRule(ip net.IP) (string, string) {
	if v4 := ip.To4(); v4 != nil {
		return "ip-cidr", v4.String() + "/32"
	}
	if v6 := ip.To16(); v6 != nil {
		return "ip6-cidr", v6.String() + "/128"
	}
	return "", ""
}

// ---------------------------------------------------------------------------
// [general]
// ---------------------------------------------------------------------------

func convertGeneral(_ map[string]interface{}) string {
	return strings.Join([]string{
		"[general]",
		"resource_parser_url = https://cdn.jsdelivr.net/gh/KOP-XIAO/QuantumultX@master/Scripts/resource-parser.js",
		"server_check_url = http://www.gstatic.com/generate_204",
		"network_check_url = http://wifi.vivo.com.cn/generate_204",
		"server_check_timeout = 5000",
		"udp_drop_list = QUIC",
	}, "\n")
}

// ---------------------------------------------------------------------------
// [dns]
// ---------------------------------------------------------------------------

func convertDNS(config map[string]interface{}) string {
	lines := []string{"[dns]"}

	dnsCfg, _ := config["dns"].(map[string]interface{})

	ipv6 := clash.MapGetBool(config, "ipv6", false)
	if dnsCfg != nil && !ipv6 {
		ipv6 = clash.MapGetBool(dnsCfg, "ipv6", false)
	}
	if !ipv6 {
		lines = append(lines, "no-ipv6")
	}

	getList := func(key string) []string {
		if dnsCfg == nil {
			return nil
		}
		return clash.ToStringSlice(dnsCfg[key])
	}

	seen := map[string]bool{}
	for _, ns := range append(getList("default-nameserver"), getList("nameserver")...) {
		ns = strings.Trim(ns, `'"`)
		if !strings.Contains(ns, "://") && !seen[ns] {
			lines = append(lines, "server = "+ns)
			seen[ns] = true
		}
	}

	seenDoh := map[string]bool{}
	dohServers := []string{}
	for _, ns := range append(getList("nameserver"), getList("fallback")...) {
		ns = strings.Trim(ns, `'"`)
		if strings.HasPrefix(ns, "https://") && !seenDoh[ns] {
			dohServers = append(dohServers, ns)
			seenDoh[ns] = true
		}
	}
	if len(dohServers) > 0 {
		lines = append(lines, "doh-server = "+strings.Join(dohServers, ","))
	}

	seenDoq := map[string]bool{}
	doqServers := []string{}
	for _, ns := range append(getList("nameserver"), getList("fallback")...) {
		ns = strings.Trim(ns, `'"`)
		if strings.HasPrefix(ns, "quic://") && !seenDoq[ns] {
			doqServers = append(doqServers, ns)
			seenDoq[ns] = true
		}
	}
	if len(doqServers) > 0 {
		lines = append(lines, "doq-server = "+strings.Join(doqServers, ","))
	}

	// nameserver-policy → per-domain server/doh-server/doq-server entries
	// +.example.com → two entries: /example.com/ and /*.example.com/
	if dnsCfg != nil {
		nsPolicy, _ := dnsCfg["nameserver-policy"].(map[string]interface{})
		if len(nsPolicy) > 0 {
			lines = append(lines, "; --- nameserver-policy ---")
			for pat, dnsRaw := range nsPolicy {
				pat = strings.TrimSpace(pat)
				if strings.HasPrefix(pat, "geosite:") || strings.HasPrefix(pat, "rule-set:") {
					lines = append(lines, fmt.Sprintf("; [WARNING] nameserver-policy pattern not supported in QX: %s", pat))
					continue
				}
				var dnsVal string
				switch v := dnsRaw.(type) {
				case []interface{}:
					if len(v) > 0 {
						dnsVal = strings.TrimSpace(fmt.Sprintf("%v", v[0]))
					}
				default:
					dnsVal = strings.TrimSpace(fmt.Sprintf("%v", v))
				}
				dnsVal = strings.Trim(dnsVal, `'"`)

				directive := "server"
				if strings.HasPrefix(dnsVal, "https://") {
					directive = "doh-server"
				} else if strings.HasPrefix(dnsVal, "quic://") {
					directive = "doq-server"
				}

				if strings.HasPrefix(pat, "+.") {
					root := pat[2:]
					lines = append(lines, fmt.Sprintf("%s = /%s/%s", directive, root, dnsVal))
					lines = append(lines, fmt.Sprintf("%s = /*.%s/%s", directive, root, dnsVal))
				} else {
					lines = append(lines, fmt.Sprintf("%s = /%s/%s", directive, pat, dnsVal))
				}
			}
		}
	}

	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// [server_local] per-protocol converters
// ---------------------------------------------------------------------------

func convertTrojan(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	password := clash.MapGetStr(p, "password", "")
	sni := clash.MapGetStr(p, "sni", "")
	skipVerify := clash.MapGetBool(p, "skip-cert-verify", false)
	udp := clash.MapGetBool(p, "udp", true)
	fastOpen := clash.MapGetBool(p, "fast-open", false)
	transport := clash.MapGetStr(p, "network", "tcp")

	parts := []string{fmt.Sprintf("trojan=%s:%d, password=%s", server, port, password)}

	if transport == "ws" {
		wsOpts, _ := clash.MapGet[map[string]interface{}](p, "ws-opts")
		wsPath, wsHost := "", ""
		if wsOpts != nil {
			wsPath = clash.MapGetStr(wsOpts, "path", "")
			if headers, ok := clash.MapGet[map[string]interface{}](wsOpts, "headers"); ok {
				wsHost = clash.MapGetStr(headers, "Host", "")
			}
		}
		parts = append(parts, "obfs=wss")
		if wsHost != "" {
			parts = append(parts, "obfs-host="+wsHost)
		} else if sni != "" {
			parts = append(parts, "obfs-host="+sni)
		}
		if wsPath != "" {
			parts = append(parts, "obfs-uri="+wsPath)
		}
	} else {
		parts = append(parts, "over-tls=true")
		if sni != "" {
			parts = append(parts, "tls-host="+sni)
		}
		parts = append(parts, "tls-verification="+clash.BoolStr(!skipVerify))
	}

	parts = append(parts, "fast-open="+clash.BoolStr(fastOpen))
	parts = append(parts, "udp-relay="+clash.BoolStr(udp))
	parts = append(parts, "tag="+name)
	return strings.Join(parts, ", ")
}

func convertSS(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	cipher := clash.MapGetStr(p, "cipher", "aes-256-gcm")
	password := clash.MapGetStr(p, "password", "")
	udp := clash.MapGetBool(p, "udp", true)
	fastOpen := clash.MapGetBool(p, "fast-open", false)

	parts := []string{fmt.Sprintf("shadowsocks=%s:%d, method=%s, password=%s", server, port, cipher, password)}

	plugin := clash.MapGetStr(p, "plugin", "")
	pluginOpts, _ := clash.MapGet[map[string]interface{}](p, "plugin-opts")
	if pluginOpts == nil {
		pluginOpts = map[string]interface{}{}
	}

	switch plugin {
	case "obfs":
		mode := clash.MapGetStr(pluginOpts, "mode", "http")
		parts = append(parts, "obfs="+mode)
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
		parts = append(parts, "; [WARNING] shadow-tls not supported in QX")
	default:
		if plugin != "" {
			parts = append(parts, "; [WARNING] unsupported SS plugin: "+plugin)
		}
	}

	parts = append(parts, "fast-open="+clash.BoolStr(fastOpen))
	parts = append(parts, "udp-relay="+clash.BoolStr(udp))
	parts = append(parts, "tag="+name)
	return strings.Join(parts, ", ")
}

func convertSSR(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	cipher := clash.MapGetStr(p, "cipher", "aes-256-cfb")
	password := clash.MapGetStr(p, "password", "")
	protocol := clash.MapGetStr(p, "protocol", "origin")
	protocolParam := clash.MapGetStr(p, "protocol-param", "")
	obfs := clash.MapGetStr(p, "obfs", "plain")
	obfsParam := clash.MapGetStr(p, "obfs-param", "")
	udp := clash.MapGetBool(p, "udp", true)
	fastOpen := clash.MapGetBool(p, "fast-open", false)

	parts := []string{fmt.Sprintf("shadowsocks=%s:%d, method=%s, password=%s", server, port, cipher, password)}
	parts = append(parts, "ssr-protocol="+protocol)
	if protocolParam != "" {
		parts = append(parts, "ssr-protocol-param="+protocolParam)
	}
	parts = append(parts, "obfs="+obfs)
	if obfsParam != "" {
		parts = append(parts, "obfs-host="+obfsParam)
	}
	parts = append(parts, "fast-open="+clash.BoolStr(fastOpen))
	parts = append(parts, "udp-relay="+clash.BoolStr(udp))
	parts = append(parts, "tag="+name)
	return strings.Join(parts, ", ")
}

func convertVmess(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	cipher := clash.MapGetStr(p, "cipher", "auto")
	if cipher == "auto" {
		cipher = "none"
	}
	uuid := clash.MapGetStr(p, "uuid", "")
	transport := clash.MapGetStr(p, "network", "tcp")
	tls := clash.MapGetBool(p, "tls", false)
	sni := clash.MapGetStr(p, "servername", "")
	if sni == "" {
		sni = clash.MapGetStr(p, "sni", "")
	}
	alterId := clash.MapGetInt(p, "alterId", 0)
	udp := clash.MapGetBool(p, "udp", true)
	fastOpen := clash.MapGetBool(p, "fast-open", false)

	parts := []string{fmt.Sprintf("vmess=%s:%d, method=%s, password=%s", server, port, cipher, uuid)}

	switch transport {
	case "ws":
		wsOpts, _ := clash.MapGet[map[string]interface{}](p, "ws-opts")
		wsPath, wsHost := "", ""
		if wsOpts != nil {
			wsPath = clash.MapGetStr(wsOpts, "path", "")
			if headers, ok := clash.MapGet[map[string]interface{}](wsOpts, "headers"); ok {
				wsHost = clash.MapGetStr(headers, "Host", "")
			}
		}
		if tls {
			parts = append(parts, "obfs=wss")
		} else {
			parts = append(parts, "obfs=ws")
		}
		if wsHost != "" {
			parts = append(parts, "obfs-host="+wsHost)
		} else if sni != "" {
			parts = append(parts, "obfs-host="+sni)
		}
		if wsPath != "" {
			parts = append(parts, "obfs-uri="+wsPath)
		}
	case "http":
		httpOpts, _ := clash.MapGet[map[string]interface{}](p, "http-opts")
		parts = append(parts, "obfs=http")
		if httpOpts != nil {
			hosts := clash.ToStringSlice(httpOpts["host"])
			if len(hosts) > 0 {
				parts = append(parts, "obfs-host="+hosts[0])
			}
			paths := clash.ToStringSlice(httpOpts["path"])
			if len(paths) > 0 {
				parts = append(parts, "obfs-uri="+paths[0])
			}
		}
	default: // tcp
		if tls {
			parts = append(parts, "obfs=over-tls")
			if sni != "" {
				parts = append(parts, "obfs-host="+sni)
			}
		}
	}

	if alterId > 0 {
		parts = append(parts, "aead=false")
	}
	parts = append(parts, "fast-open="+clash.BoolStr(fastOpen))
	parts = append(parts, "udp-relay="+clash.BoolStr(udp))
	parts = append(parts, "tag="+name)
	return strings.Join(parts, ", ")
}

func convertVless(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	uuid := clash.MapGetStr(p, "uuid", "")
	transport := clash.MapGetStr(p, "network", "tcp")
	tls := clash.MapGetBool(p, "tls", false)
	sni := clash.MapGetStr(p, "servername", "")
	if sni == "" {
		sni = clash.MapGetStr(p, "sni", "")
	}
	flow := clash.MapGetStr(p, "flow", "")
	udp := clash.MapGetBool(p, "udp", true)
	fastOpen := clash.MapGetBool(p, "fast-open", false)

	parts := []string{fmt.Sprintf("vless=%s:%d, method=none, password=%s", server, port, uuid)}

	realityOpts, hasReality := clash.MapGet[map[string]interface{}](p, "reality-opts")
	if hasReality && realityOpts != nil {
		parts = append(parts, "obfs=over-tls")
		if sni != "" {
			parts = append(parts, "obfs-host="+sni)
		}
		if pubKey := clash.MapGetStr(realityOpts, "public-key", ""); pubKey != "" {
			parts = append(parts, "reality-base64-pubkey="+pubKey)
		}
		if shortID := clash.MapGetStr(realityOpts, "short-id", ""); shortID != "" {
			parts = append(parts, "reality-hex-shortid="+shortID)
		}
		if flow != "" {
			parts = append(parts, "vless-flow="+flow)
		}
	} else {
		switch transport {
		case "ws":
			wsOpts, _ := clash.MapGet[map[string]interface{}](p, "ws-opts")
			wsPath, wsHost := "", ""
			if wsOpts != nil {
				wsPath = clash.MapGetStr(wsOpts, "path", "")
				if headers, ok := clash.MapGet[map[string]interface{}](wsOpts, "headers"); ok {
					wsHost = clash.MapGetStr(headers, "Host", "")
				}
			}
			if tls {
				parts = append(parts, "obfs=wss")
			} else {
				parts = append(parts, "obfs=ws")
			}
			if wsHost != "" {
				parts = append(parts, "obfs-host="+wsHost)
			} else if sni != "" {
				parts = append(parts, "obfs-host="+sni)
			}
			if wsPath != "" {
				parts = append(parts, "obfs-uri="+wsPath)
			}
		default: // tcp
			if tls {
				parts = append(parts, "obfs=over-tls")
				if sni != "" {
					parts = append(parts, "obfs-host="+sni)
				}
			}
		}
	}

	parts = append(parts, "fast-open="+clash.BoolStr(fastOpen))
	parts = append(parts, "udp-relay="+clash.BoolStr(udp))
	parts = append(parts, "tag="+name)
	return strings.Join(parts, ", ")
}

func convertHysteria2(p map[string]interface{}) string {
	return "; [WARNING] Hysteria2 not natively supported in Quantumult X: " + clash.MapGetStr(p, "name", "")
}

func convertSocks5(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	username := clash.MapGetStr(p, "username", "")
	password := clash.MapGetStr(p, "password", "")
	tls := clash.MapGetBool(p, "tls", false)
	sni := clash.MapGetStr(p, "sni", "")
	skipVerify := clash.MapGetBool(p, "skip-cert-verify", false)
	udp := clash.MapGetBool(p, "udp", true)
	fastOpen := clash.MapGetBool(p, "fast-open", false)

	parts := []string{fmt.Sprintf("socks5=%s:%d", server, port)}
	if username != "" {
		parts = append(parts, "username="+username)
	}
	if password != "" {
		parts = append(parts, "password="+password)
	}
	if tls {
		parts = append(parts, "over-tls=true")
		if sni != "" {
			parts = append(parts, "tls-host="+sni)
		}
		parts = append(parts, "tls-verification="+clash.BoolStr(!skipVerify))
	}
	parts = append(parts, "fast-open="+clash.BoolStr(fastOpen))
	parts = append(parts, "udp-relay="+clash.BoolStr(udp))
	parts = append(parts, "tag="+name)
	return strings.Join(parts, ", ")
}

func convertHTTP(p map[string]interface{}) string {
	name := clash.MapGetStr(p, "name", "")
	server := clash.MapGetStr(p, "server", "")
	port := clash.MapGetInt(p, "port", 0)
	username := clash.MapGetStr(p, "username", "")
	password := clash.MapGetStr(p, "password", "")
	tls := clash.MapGetBool(p, "tls", false)
	sni := clash.MapGetStr(p, "sni", "")
	skipVerify := clash.MapGetBool(p, "skip-cert-verify", false)

	fastOpen := clash.MapGetBool(p, "fast-open", false)
	udp := clash.MapGetBool(p, "udp", false)

	parts := []string{fmt.Sprintf("http=%s:%d", server, port)}
	if username != "" {
		parts = append(parts, "username="+username)
	}
	if password != "" {
		parts = append(parts, "password="+password)
	}
	if tls {
		parts = append(parts, "over-tls=true")
		if sni != "" {
			parts = append(parts, "tls-host="+sni)
		}
		parts = append(parts, "tls-verification="+clash.BoolStr(!skipVerify))
	}
	parts = append(parts, "fast-open="+clash.BoolStr(fastOpen))
	parts = append(parts, "udp-relay="+clash.BoolStr(udp))
	parts = append(parts, "tag="+name)
	return strings.Join(parts, ", ")
}

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

// ---------------------------------------------------------------------------
// [server_local]
// ---------------------------------------------------------------------------

func convertServerLocal(proxies []map[string]interface{}) (string, []string) {
	lines := []string{"[server_local]"}
	var warnings []string
	for _, p := range proxies {
		ptype := strings.ToLower(clash.MapGetStr(p, "type", ""))
		conv, ok := proxyConverters[ptype]
		if !ok {
			w := fmt.Sprintf("Unsupported proxy type '%s': %s", ptype, clash.MapGetStr(p, "name", "?"))
			warnings = append(warnings, w)
			lines = append(lines, "; [WARNING] "+w)
			continue
		}
		lines = append(lines, conv(p))
	}
	return strings.Join(lines, "\n"), warnings
}

// ---------------------------------------------------------------------------
// [server_remote]
// ---------------------------------------------------------------------------

func convertServerRemote(providers map[string]interface{}, providerOrder []string) string {
	lines := []string{"[server_remote]"}
	for _, alias := range providerOrder {
		raw := providers[alias]
		cfg, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		url := clash.MapGetStr(cfg, "url", "")
		interval := clash.MapGetInt(cfg, "interval", 86400)
		lines = append(lines, fmt.Sprintf("%s, tag=%s, opt-parser=true, update-interval=%d, enabled=true", url, alias, interval))
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// [policy]
// ---------------------------------------------------------------------------

func convertPolicy(groups []map[string]interface{}) string {
	lines := []string{"[policy]"}

	for _, g := range groups {
		name := clash.MapGetStr(g, "name", "")
		gtype := clash.MapGetStr(g, "type", "select")
		uses := clash.ToStringSlice(g["use"])
		filter := clash.MapGetStr(g, "filter", "")
		interval := clash.MapGetInt(g, "interval", 600)
		tolerance := clash.MapGetInt(g, "tolerance", 100)

		rawProxies := clash.ToStringSlice(g["proxies"])
		members := make([]string, len(rawProxies))
		for i, px := range rawProxies {
			members[i] = lowerPolicy(px)
		}

		var resourceTag string
		switch len(uses) {
		case 0:
		case 1:
			resourceTag = uses[0]
		default:
			resourceTag = "^(" + strings.Join(uses, "|") + ")$"
		}

		buildTokens := func(extra ...string) string {
			var tokens []string
			tokens = append(tokens, members...)
			if resourceTag != "" {
				tokens = append(tokens, "resource-tag-regex="+resourceTag)
				if filter != "" {
					tokens = append(tokens, "server-tag-regex="+filter)
				}
			}
			tokens = append(tokens, extra...)
			return strings.Join(tokens, ", ")
		}

		switch gtype {
		case "select":
			lines = append(lines, fmt.Sprintf("static = %s, %s", name, buildTokens()))
		case "url-test":
			lines = append(lines, fmt.Sprintf("url-latency-benchmark = %s, %s", name,
				buildTokens(
					fmt.Sprintf("check-interval=%d", interval),
					"alive-checking=false",
					fmt.Sprintf("tolerance=%d", tolerance),
				)))
		case "fallback":
			lines = append(lines, fmt.Sprintf("available = %s, %s", name, buildTokens()))
		case "load-balance":
			lines = append(lines, fmt.Sprintf("round-robin = %s, %s", name, buildTokens()))
		case "relay":
			lines = append(lines, fmt.Sprintf("; [NOTE] relay group '%s' — configure as proxy chain in [filter_local]", name))
		default:
			lines = append(lines, fmt.Sprintf("; [WARNING] Unknown group type '%s': %s", gtype, name))
		}
	}

	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// [filter_remote] + [filter_local]
// ---------------------------------------------------------------------------

func convertFilters(
	rules []interface{},
	ruleProviders map[string]interface{},
	proxies []map[string]interface{},
	proxyChainGroups map[string]bool,
) (filterLocal string, filterRemote string, warnings []string) {

	providerURLs := map[string]string{}
	for rpName, rpCfgRaw := range ruleProviders {
		if rpCfg, ok := rpCfgRaw.(map[string]interface{}); ok {
			providerURLs[rpName] = clash.MapGetStr(rpCfg, "url", "")
		}
	}

	// Build chain server routing rules from resolved server IPs. QX needs the
	// proxy's outbound connection to hit the dialer policy by destination IP.
	chainRoutes, chainWarnings := chainServerIPRoutes(proxies)
	warnings = append(warnings, chainWarnings...)

	localLines := []string{"[filter_local]"}
	if len(chainRoutes) > 0 {
		localLines = append(localLines, "; --- proxy chain server routes (dialer-proxy) ---")
		localLines = append(localLines, chainRoutes...)
	}

	remoteLines := []string{"[filter_remote]"}
	seenRemote := map[string]bool{}

	// via-interface=%TUN% forces traffic through TUN so QX re-evaluates routing,
	// which lets the chain server routes at the top of [filter_local] redirect
	// the proxy's outbound connection through the transit (dialer-proxy) proxy.
	via := func(policy string) string {
		if proxyChainGroups[policy] {
			return ", via-interface=%TUN%"
		}
		return ""
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
			policy := "proxy"
			if len(parts) > 2 {
				policy = lowerPolicy(parts[2])
			}
			rawURL := providerURLs[rpName]
			if rawURL == "" {
				localLines = append(localLines, fmt.Sprintf("; [WARNING] rule-provider '%s' not found", rpName))
				continue
			}
			loonURL := convertRuleProviderURL(rawURL)
			if !seenRemote[rpName] {
				if strings.Contains(rawURL, "ACL4SSR") {
					remoteLines = append(remoteLines, "; [NOTE] ACL4SSR URL — verify QX compatibility")
				}
				remoteLines = append(remoteLines, fmt.Sprintf("%s, tag=%s, force-policy=%s, enabled=true", loonURL, rpName, policy))
				seenRemote[rpName] = true
			}

		case "MATCH":
			policy := lowerPolicy(parts[1])
			localLines = append(localLines, "final, "+policy+via(policy))

		case "DOMAIN-SUFFIX":
			if len(parts) < 3 {
				continue
			}
			policy := lowerPolicy(parts[2])
			localLines = append(localLines, fmt.Sprintf("host-suffix, %s, %s%s", parts[1], policy, via(policy)))

		case "DOMAIN":
			if len(parts) < 3 {
				continue
			}
			policy := lowerPolicy(parts[2])
			localLines = append(localLines, fmt.Sprintf("host, %s, %s%s", parts[1], policy, via(policy)))

		case "DOMAIN-KEYWORD":
			if len(parts) < 3 {
				continue
			}
			policy := lowerPolicy(parts[2])
			localLines = append(localLines, fmt.Sprintf("host-keyword, %s, %s%s", parts[1], policy, via(policy)))

		case "DOMAIN-WILDCARD":
			if len(parts) < 3 {
				continue
			}
			policy := lowerPolicy(parts[2])
			localLines = append(localLines, fmt.Sprintf("host-wildcard, %s, %s%s", parts[1], policy, via(policy)))

		case "IP-ASN":
			if len(parts) < 3 {
				continue
			}
			policy := lowerPolicy(parts[2])
			localLines = append(localLines, fmt.Sprintf("ip-asn, %s, %s%s", parts[1], policy, via(policy)))

		case "IP-CIDR":
			if len(parts) < 3 {
				continue
			}
			policy := lowerPolicy(parts[2])
			localLines = append(localLines, fmt.Sprintf("ip-cidr, %s, %s%s", parts[1], policy, via(policy)))

		case "IP-CIDR6":
			if len(parts) < 3 {
				continue
			}
			policy := lowerPolicy(parts[2])
			localLines = append(localLines, fmt.Sprintf("ip6-cidr, %s, %s%s", parts[1], policy, via(policy)))

		case "GEOIP":
			if len(parts) < 3 {
				continue
			}
			policy := lowerPolicy(parts[2])
			localLines = append(localLines, fmt.Sprintf("geoip, %s, %s%s", strings.ToLower(parts[1]), policy, via(policy)))

		default:
			w := fmt.Sprintf("Unsupported rule type in QX: %s", strings.Join(parts, ","))
			if unsupportedRuleTypes[ruleType] {
				localLines = append(localLines, "; [WARNING] "+w)
				warnings = append(warnings, w)
			} else {
				localLines = append(localLines, "; [WARNING] Unknown rule type: "+strings.Join(parts, ","))
			}
		}
	}

	return strings.Join(localLines, "\n"), strings.Join(remoteLines, "\n"), warnings
}

// ---------------------------------------------------------------------------
// Top-level assembler
// ---------------------------------------------------------------------------

func convert(config map[string]interface{}, root *yaml.Node) (string, []string) {
	var allWarnings []string
	sections := []string{}

	sections = append(sections, convertGeneral(config))
	sections = append(sections, convertDNS(config))

	proxies := clash.ToMapSlice(config["proxies"])
	groups := clash.ToMapSlice(config["proxy-groups"])
	_, proxyChainGroups := buildChainInfo(proxies, groups)

	sections = append(sections, convertPolicy(groups))

	providerOrder := clash.OrderedKeysFromNode(root, "proxy-providers")
	_, providersMap := clash.ToOrderedMap(config["proxy-providers"])
	if providersMap == nil {
		providersMap = map[string]interface{}{}
	}
	if len(providerOrder) == 0 {
		providerOrder, _ = clash.ToOrderedMap(config["proxy-providers"])
	}
	sections = append(sections, convertServerRemote(providersMap, providerOrder))

	rules, _ := config["rules"].([]interface{})
	_, ruleProvidersMap := clash.ToOrderedMap(config["rule-providers"])
	if ruleProvidersMap == nil {
		ruleProvidersMap = map[string]interface{}{}
	}

	filterLocalText, filterRemoteText, filterWarnings := convertFilters(rules, ruleProvidersMap, proxies, proxyChainGroups)
	allWarnings = append(allWarnings, filterWarnings...)

	sections = append(sections, filterRemoteText)
	sections = append(sections, "[rewrite_remote]")

	serverLocalText, serverWarnings := convertServerLocal(proxies)
	allWarnings = append(allWarnings, serverWarnings...)
	sections = append(sections, serverLocalText)

	sections = append(sections, filterLocalText)
	sections = append(sections, "[rewrite_local]")
	sections = append(sections, "[task_local]")
	sections = append(sections, "[http_backend]")
	sections = append(sections, "[mitm]")

	return strings.Join(sections, "\n\n") + "\n", allWarnings
}
