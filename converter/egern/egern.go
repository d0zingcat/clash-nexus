// Package egern converts a Clash (mihomo) YAML config to an Egern YAML config.
package egern

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"clash-nexus/converter/clash"
)

// Converter converts Clash YAML to Egern YAML format.
type Converter struct{}

// New returns a new Egern Converter.
func New() *Converter { return &Converter{} }

// Name returns the short identifier for this converter.
func (c *Converter) Name() string { return "egern" }

// DefaultExtension returns the file extension for Egern configs.
func (c *Converter) DefaultExtension() string { return ".yaml" }

// Convert transforms a Clash config map into an Egern YAML byte slice.
func (c *Converter) Convert(config map[string]interface{}, root *yaml.Node) ([]byte, error) {
	out := buildEgernConfig(config, root)
	return yaml.Marshal(out)
}

// ---------------------------------------------------------------------------
// Top-level config assembly
// ---------------------------------------------------------------------------

func buildEgernConfig(config map[string]interface{}, root *yaml.Node) map[string]interface{} {
	out := map[string]interface{}{}

	// IPv6
	if ipv6 := clash.MapGetBool(config, "ipv6", false); ipv6 {
		out["ipv6"] = true
	}

	// Ports
	mixedPort := clash.MapGetInt(config, "mixed-port", 0)
	httpPort := clash.MapGetInt(config, "port", 0)
	socksPort := clash.MapGetInt(config, "socks-port", 0)
	if mixedPort > 0 {
		out["http_port"] = mixedPort
		out["socks_port"] = mixedPort
	} else {
		if httpPort > 0 {
			out["http_port"] = httpPort
		}
		if socksPort > 0 {
			out["socks_port"] = socksPort
		}
	}

	// Allow external connections
	if clash.MapGetBool(config, "allow-lan", false) {
		out["allow_external_connections"] = true
	}

	// Standard bypass
	out["bypass_tunnel_proxy"] = []string{
		"*.local",
		"192.168.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/12",
	}

	// real_ip_domains from fake-ip-filter
	dnsCfg, _ := clash.MapGet[map[string]interface{}](config, "dns")
	if dnsCfg != nil {
		fakeIPFilter := clash.ToStringSlice(dnsCfg["fake-ip-filter"])
		realIPs := make([]string, 0, len(fakeIPFilter))
		for _, f := range fakeIPFilter {
			if f != "*" {
				realIPs = append(realIPs, f)
			}
		}
		if len(realIPs) > 0 {
			out["real_ip_domains"] = realIPs
		}
	}

	out["hijack_dns"] = []string{"*"}

	// DNS
	if egernDNS := buildEgernDNS(config); egernDNS != nil {
		out["dns"] = egernDNS
	}

	// Proxy providers map (needed for policy_groups)
	providerOrder := clash.OrderedKeysFromNode(root, "proxy-providers")
	_, providersMap := clash.ToOrderedMap(config["proxy-providers"])
	if providersMap == nil {
		providersMap = map[string]interface{}{}
	}
	if len(providerOrder) == 0 {
		providerOrder, _ = clash.ToOrderedMap(config["proxy-providers"])
	}

	// Proxies
	proxies := clash.ToMapSlice(config["proxies"])
	if egernProxies := buildEgernProxies(proxies); len(egernProxies) > 0 {
		out["proxies"] = egernProxies
	}

	// Policy groups
	groups := clash.ToMapSlice(config["proxy-groups"])
	if egernGroups := buildEgernPolicyGroups(groups, providersMap, providerOrder); len(egernGroups) > 0 {
		out["policy_groups"] = egernGroups
	}

	// Rules
	rules, _ := config["rules"].([]interface{})
	ruleProviderOrder := clash.OrderedKeysFromNode(root, "rule-providers")
	_, ruleProvidersMap := clash.ToOrderedMap(config["rule-providers"])
	if ruleProvidersMap == nil {
		ruleProvidersMap = map[string]interface{}{}
	}
	if len(ruleProviderOrder) == 0 {
		ruleProviderOrder, _ = clash.ToOrderedMap(config["rule-providers"])
	}
	if egernRules := buildEgernRules(rules, ruleProvidersMap, ruleProviderOrder); len(egernRules) > 0 {
		out["rules"] = egernRules
	}

	return out
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

func buildEgernDNS(config map[string]interface{}) map[string]interface{} {
	dnsCfg, _ := clash.MapGet[map[string]interface{}](config, "dns")

	hostsMap, _ := config["hosts"].(map[string]interface{})
	var nsPolicy map[string]interface{}
	if dnsCfg != nil {
		nsPolicy, _ = dnsCfg["nameserver-policy"].(map[string]interface{})
	}

	if dnsCfg == nil && len(hostsMap) == 0 {
		return nil
	}

	out := map[string]interface{}{}

	// Bootstrap from default-nameserver
	bootstrap := []string{}
	if dnsCfg != nil {
		for _, ns := range clash.ToStringSlice(dnsCfg["default-nameserver"]) {
			ns = strings.Trim(ns, `'"`)
			if ns != "" {
				bootstrap = append(bootstrap, ns)
			}
		}
	}
	if len(bootstrap) == 0 {
		bootstrap = []string{"system"}
	}
	out["bootstrap"] = bootstrap

	// Upstreams: categorise nameservers by protocol
	if dnsCfg != nil {
		udpServers := []string{}
		dohServers := []string{}
		dotServers := []string{}
		doqServers := []string{}

		allNameservers := append(
			clash.ToStringSlice(dnsCfg["nameserver"]),
			clash.ToStringSlice(dnsCfg["fallback"])...,
		)
		seenNS := map[string]bool{}
		for _, ns := range allNameservers {
			ns = strings.Trim(ns, `'"`)
			if ns == "" || seenNS[ns] {
				continue
			}
			seenNS[ns] = true
			switch {
			case strings.HasPrefix(ns, "https://"):
				dohServers = append(dohServers, ns)
			case strings.HasPrefix(ns, "tls://"):
				dotServers = append(dotServers, ns)
			case strings.HasPrefix(ns, "quic://"):
				doqServers = append(doqServers, ns)
			default:
				udpServers = append(udpServers, ns)
			}
		}

		upstreams := map[string]interface{}{}
		if len(udpServers) > 0 {
			upstreams["default"] = udpServers
		}
		if len(dohServers) > 0 {
			upstreams["doh"] = dohServers
		}
		if len(dotServers) > 0 {
			upstreams["dot"] = dotServers
		}
		if len(doqServers) > 0 {
			upstreams["doq"] = doqServers
		}
		if len(upstreams) > 0 {
			out["upstreams"] = upstreams
		}

		// Determine catch-all upstream name (prefer DoH > DoQ > DoT > default)
		catchAll := ""
		switch {
		case len(dohServers) > 0:
			catchAll = "doh"
		case len(doqServers) > 0:
			catchAll = "doq"
		case len(dotServers) > 0:
			catchAll = "dot"
		case len(udpServers) > 0:
			catchAll = "default"
		}

		// Forward rules from nameserver-policy
		forward := []map[string]interface{}{}

		if nsPolicy != nil {
			for pattern, dnsServerRaw := range nsPolicy {
				pattern = strings.TrimSpace(pattern)
				// Determine Egern upstream name for the target
				var targetUpstream string
				var serverStr string
				switch v := dnsServerRaw.(type) {
				case []interface{}:
					if len(v) > 0 {
						serverStr = strings.TrimSpace(fmt.Sprintf("%v", v[0]))
					}
				default:
					serverStr = strings.TrimSpace(fmt.Sprintf("%v", v))
				}
				serverStr = strings.Trim(serverStr, `'"`)
				if serverStr == "system" || serverStr == "" {
					targetUpstream = "bootstrap"
				} else if strings.HasPrefix(serverStr, "https://") {
					targetUpstream = "doh"
				} else if strings.HasPrefix(serverStr, "tls://") {
					targetUpstream = "dot"
				} else if strings.HasPrefix(serverStr, "quic://") {
					targetUpstream = "doq"
				} else {
					targetUpstream = "default"
				}

				// Convert Clash pattern to Egern forward rule type
				if strings.HasPrefix(pattern, "geosite:") || strings.HasPrefix(pattern, "rule-set:") {
					// Not directly supported; emit as comment via a note
					forward = append(forward, map[string]interface{}{
						"_note": fmt.Sprintf("# [WARNING] pattern not supported in Egern: %s", pattern),
					})
					continue
				}
				if strings.HasPrefix(pattern, "+.") {
					// +.cn → domain_suffix cn
					suffix := pattern[2:]
					forward = append(forward, map[string]interface{}{
						"domain_suffix": map[string]interface{}{
							"match": suffix,
							"value": targetUpstream,
						},
					})
					// Also add wildcard for *.suffix
					forward = append(forward, map[string]interface{}{
						"wildcard": map[string]interface{}{
							"match": "*." + suffix,
							"value": targetUpstream,
						},
					})
				} else if strings.Contains(pattern, "*") {
					forward = append(forward, map[string]interface{}{
						"wildcard": map[string]interface{}{
							"match": pattern,
							"value": targetUpstream,
						},
					})
				} else {
					forward = append(forward, map[string]interface{}{
						"domain": map[string]interface{}{
							"match": pattern,
							"value": targetUpstream,
						},
					})
				}
			}
		}

		// Add catch-all forward rule
		if catchAll != "" {
			forward = append(forward, map[string]interface{}{
				"wildcard": map[string]interface{}{
					"match": "*",
					"value": catchAll,
				},
			})
		}

		if len(forward) > 0 {
			// Filter out _note entries (comments aren't valid YAML map entries in practice)
			cleanForward := make([]map[string]interface{}, 0, len(forward))
			for _, f := range forward {
				if _, isNote := f["_note"]; !isNote {
					cleanForward = append(cleanForward, f)
				}
			}
			if len(cleanForward) > 0 {
				out["forward"] = cleanForward
			}
		}
	}

	// Hosts
	if len(hostsMap) > 0 {
		out["hosts"] = hostsMap
	}

	if len(out) <= 1 { // only bootstrap
		return nil
	}
	return out
}

// ---------------------------------------------------------------------------
// Proxies
// ---------------------------------------------------------------------------

func buildEgernProxies(proxies []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(proxies))
	for _, p := range proxies {
		ptype := strings.ToLower(clash.MapGetStr(p, "type", ""))
		var entry map[string]interface{}
		switch ptype {
		case "ss":
			entry = convertSSToEgern(p)
		case "trojan":
			entry = convertTrojanToEgern(p)
		case "vmess":
			entry = convertVmessToEgern(p)
		case "vless":
			entry = convertVlessToEgern(p)
		case "hysteria2":
			entry = convertHysteria2ToEgern(p)
		case "socks5":
			entry = convertSocks5ToEgern(p)
		case "http":
			entry = convertHTTPToEgern(p)
		default:
			// Unsupported (e.g. ssr, tuic, wireguard need manual handling)
			name := clash.MapGetStr(p, "name", "?")
			_ = name
			// Skip unsupported types silently (they get a comment if we had text output)
			continue
		}
		if entry != nil {
			// Handle dialer-proxy → prev_hop
			if dialer := clash.MapGetStr(p, "dialer-proxy", ""); dialer != "" {
				for _, v := range entry {
					if cfg, ok := v.(map[string]interface{}); ok {
						cfg["prev_hop"] = dialer
					}
				}
			}
			out = append(out, entry)
		}
	}
	return out
}

func convertSSToEgern(p map[string]interface{}) map[string]interface{} {
	ss := map[string]interface{}{
		"name":     clash.MapGetStr(p, "name", ""),
		"method":   clash.MapGetStr(p, "cipher", "aes-256-gcm"),
		"password": clash.MapGetStr(p, "password", ""),
		"server":   clash.MapGetStr(p, "server", ""),
		"port":     clash.MapGetInt(p, "port", 0),
	}
	if clash.MapGetBool(p, "udp", false) {
		ss["udp_relay"] = true
	}
	if clash.MapGetBool(p, "fast-open", false) {
		ss["tfo"] = true
	}

	plugin := clash.MapGetStr(p, "plugin", "")
	pluginOpts, _ := clash.MapGet[map[string]interface{}](p, "plugin-opts")
	if pluginOpts == nil {
		pluginOpts = map[string]interface{}{}
	}
	switch plugin {
	case "obfs":
		ss["obfs"] = clash.MapGetStr(pluginOpts, "mode", "http")
		if host := clash.MapGetStr(pluginOpts, "host", ""); host != "" {
			ss["obfs_host"] = host
		}
		uri := clash.MapGetStr(pluginOpts, "uri", "")
		if uri == "" {
			uri = clash.MapGetStr(pluginOpts, "path", "")
		}
		if uri != "" {
			ss["obfs_uri"] = uri
		}
	case "shadow-tls":
		stls := map[string]interface{}{}
		if pw := clash.MapGetStr(pluginOpts, "password", ""); pw != "" {
			stls["password"] = pw
		}
		if host := clash.MapGetStr(pluginOpts, "host", ""); host != "" {
			stls["sni"] = host
		}
		if ver := clash.MapGetInt(pluginOpts, "version", 3); ver > 0 {
			stls["version"] = ver
		}
		if len(stls) > 0 {
			ss["shadow_tls"] = stls
		}
	}
	return map[string]interface{}{"shadowsocks": ss}
}

func convertTrojanToEgern(p map[string]interface{}) map[string]interface{} {
	tr := map[string]interface{}{
		"name":     clash.MapGetStr(p, "name", ""),
		"server":   clash.MapGetStr(p, "server", ""),
		"port":     clash.MapGetInt(p, "port", 0),
		"password": clash.MapGetStr(p, "password", ""),
	}
	if sni := clash.MapGetStr(p, "sni", ""); sni != "" {
		tr["sni"] = sni
	}
	if clash.MapGetBool(p, "skip-cert-verify", false) {
		tr["skip_tls_verify"] = true
	}
	if clash.MapGetBool(p, "udp", false) {
		tr["udp_relay"] = true
	}
	if clash.MapGetBool(p, "fast-open", false) {
		tr["tfo"] = true
	}

	// WebSocket transport
	network := clash.MapGetStr(p, "network", "tcp")
	if network == "ws" {
		wsOpts, _ := clash.MapGet[map[string]interface{}](p, "ws-opts")
		ws := map[string]interface{}{}
		if wsOpts != nil {
			if path := clash.MapGetStr(wsOpts, "path", ""); path != "" {
				ws["path"] = path
			}
			if headers, ok := clash.MapGet[map[string]interface{}](wsOpts, "headers"); ok {
				if host := clash.MapGetStr(headers, "Host", ""); host != "" {
					ws["host"] = host
				}
			}
		}
		tr["websocket"] = ws
	}
	return map[string]interface{}{"trojan": tr}
}

func buildVmessVlessTransport(network string, tls bool, sni string, skipVerify bool,
	wsOpts, httpOpts, grpcOpts, realityOpts map[string]interface{},
	hasReality bool) map[string]interface{} {

	switch network {
	case "ws":
		ws := map[string]interface{}{}
		if wsOpts != nil {
			if path := clash.MapGetStr(wsOpts, "path", ""); path != "" {
				ws["path"] = path
			}
			if headers, ok := clash.MapGet[map[string]interface{}](wsOpts, "headers"); ok {
				if host := clash.MapGetStr(headers, "Host", ""); host != "" {
					if tls {
						ws["sni"] = host
					} else {
						if ws["headers"] == nil {
							ws["headers"] = map[string]interface{}{}
						}
						ws["headers"].(map[string]interface{})["Host"] = host
					}
				}
			}
		}
		if sni != "" && tls {
			ws["sni"] = sni
		}
		if skipVerify && tls {
			ws["skip_tls_verify"] = true
		}
		if tls {
			return map[string]interface{}{"wss": ws}
		}
		return map[string]interface{}{"ws": ws}

	case "h2", "http":
		h2 := map[string]interface{}{}
		src := wsOpts
		if httpOpts != nil {
			src = httpOpts
		}
		if src != nil {
			paths := clash.ToStringSlice(src["path"])
			if len(paths) > 0 {
				h2["path"] = paths[0]
			}
			hosts := clash.ToStringSlice(src["host"])
			if len(hosts) > 0 {
				h2["sni"] = hosts[0]
			}
		}
		if sni != "" {
			h2["sni"] = sni
		}
		if skipVerify {
			h2["skip_tls_verify"] = true
		}
		if network == "h2" {
			return map[string]interface{}{"http2": h2}
		}
		return map[string]interface{}{"http1": h2}

	case "tcp", "":
		if hasReality && realityOpts != nil {
			tlsMap := map[string]interface{}{}
			if sni != "" {
				tlsMap["sni"] = sni
			}
			reality := map[string]interface{}{}
			if pubKey := clash.MapGetStr(realityOpts, "public-key", ""); pubKey != "" {
				reality["public_key"] = pubKey
			}
			if shortID := clash.MapGetStr(realityOpts, "short-id", ""); shortID != "" {
				reality["short_id"] = shortID
			}
			tlsMap["reality"] = reality
			return map[string]interface{}{"tls": tlsMap}
		}
		if tls {
			tlsMap := map[string]interface{}{}
			if sni != "" {
				tlsMap["sni"] = sni
			}
			if skipVerify {
				tlsMap["skip_tls_verify"] = true
			}
			return map[string]interface{}{"tls": tlsMap}
		}

	case "grpc":
		// gRPC not directly supported in Egern; fall through to nil
	}
	return nil
}

func convertVmessToEgern(p map[string]interface{}) map[string]interface{} {
	vm := map[string]interface{}{
		"name":     clash.MapGetStr(p, "name", ""),
		"server":   clash.MapGetStr(p, "server", ""),
		"port":     clash.MapGetInt(p, "port", 0),
		"user_id":  clash.MapGetStr(p, "uuid", ""),
		"security": clash.MapGetStr(p, "cipher", "auto"),
	}
	alterId := clash.MapGetInt(p, "alterId", 0)
	if alterId > 0 {
		vm["legacy"] = true
	}
	if clash.MapGetBool(p, "udp", false) {
		vm["udp_relay"] = true
	}
	if clash.MapGetBool(p, "tfo", false) {
		vm["tfo"] = true
	}

	network := clash.MapGetStr(p, "network", "tcp")
	tls := clash.MapGetBool(p, "tls", false)
	sni := clash.MapGetStr(p, "servername", "")
	if sni == "" {
		sni = clash.MapGetStr(p, "sni", "")
	}
	skipVerify := clash.MapGetBool(p, "skip-cert-verify", false)

	wsOpts, _ := clash.MapGet[map[string]interface{}](p, "ws-opts")
	httpOpts, _ := clash.MapGet[map[string]interface{}](p, "http-opts")

	if t := buildVmessVlessTransport(network, tls, sni, skipVerify, wsOpts, httpOpts, nil, nil, false); t != nil {
		vm["transport"] = t
	}
	return map[string]interface{}{"vmess": vm}
}

func convertVlessToEgern(p map[string]interface{}) map[string]interface{} {
	vl := map[string]interface{}{
		"name":    clash.MapGetStr(p, "name", ""),
		"server":  clash.MapGetStr(p, "server", ""),
		"port":    clash.MapGetInt(p, "port", 0),
		"user_id": clash.MapGetStr(p, "uuid", ""),
	}
	if flow := clash.MapGetStr(p, "flow", ""); flow != "" {
		vl["flow"] = flow
	}
	if clash.MapGetBool(p, "udp", false) {
		vl["udp_relay"] = true
	}
	if clash.MapGetBool(p, "tfo", false) {
		vl["tfo"] = true
	}

	network := clash.MapGetStr(p, "network", "tcp")
	tls := clash.MapGetBool(p, "tls", false)
	sni := clash.MapGetStr(p, "servername", "")
	if sni == "" {
		sni = clash.MapGetStr(p, "sni", "")
	}
	skipVerify := clash.MapGetBool(p, "skip-cert-verify", false)

	realityOpts, hasReality := clash.MapGet[map[string]interface{}](p, "reality-opts")
	wsOpts, _ := clash.MapGet[map[string]interface{}](p, "ws-opts")

	if t := buildVmessVlessTransport(network, tls || hasReality, sni, skipVerify, wsOpts, nil, nil, realityOpts, hasReality); t != nil {
		vl["transport"] = t
	}
	return map[string]interface{}{"vless": vl}
}

func convertHysteria2ToEgern(p map[string]interface{}) map[string]interface{} {
	hy := map[string]interface{}{
		"name":   clash.MapGetStr(p, "name", ""),
		"server": clash.MapGetStr(p, "server", ""),
		"port":   clash.MapGetInt(p, "port", 0),
		"auth":   clash.MapGetStr(p, "password", ""),
	}
	if sni := clash.MapGetStr(p, "sni", ""); sni != "" {
		hy["sni"] = sni
	}
	if clash.MapGetBool(p, "skip-cert-verify", false) {
		hy["skip_tls_verify"] = true
	}
	// Hysteria2 obfs
	if obfsType := clash.MapGetStr(p, "obfs", ""); obfsType != "" {
		hy["obfs"] = obfsType
		if obfsPw := clash.MapGetStr(p, "obfs-password", ""); obfsPw != "" {
			hy["obfs_password"] = obfsPw
		}
	}
	return map[string]interface{}{"hysteria2": hy}
}

func convertSocks5ToEgern(p map[string]interface{}) map[string]interface{} {
	s5 := map[string]interface{}{
		"name":   clash.MapGetStr(p, "name", ""),
		"server": clash.MapGetStr(p, "server", ""),
		"port":   clash.MapGetInt(p, "port", 0),
	}
	if u := clash.MapGetStr(p, "username", ""); u != "" {
		s5["username"] = u
	}
	if pw := clash.MapGetStr(p, "password", ""); pw != "" {
		s5["password"] = pw
	}
	if clash.MapGetBool(p, "udp", false) {
		s5["udp_relay"] = true
	}
	if clash.MapGetBool(p, "tfo", false) {
		s5["tfo"] = true
	}
	return map[string]interface{}{"socks5": s5}
}

func convertHTTPToEgern(p map[string]interface{}) map[string]interface{} {
	h := map[string]interface{}{
		"name":   clash.MapGetStr(p, "name", ""),
		"server": clash.MapGetStr(p, "server", ""),
		"port":   clash.MapGetInt(p, "port", 0),
	}
	if u := clash.MapGetStr(p, "username", ""); u != "" {
		h["username"] = u
	}
	if pw := clash.MapGetStr(p, "password", ""); pw != "" {
		h["password"] = pw
	}
	// Distinguish HTTP vs HTTPS
	protoKey := "http"
	if clash.MapGetBool(p, "tls", false) {
		protoKey = "https"
		if sni := clash.MapGetStr(p, "sni", ""); sni != "" {
			h["sni"] = sni
		}
		if clash.MapGetBool(p, "skip-cert-verify", false) {
			h["skip_tls_verify"] = true
		}
	}
	return map[string]interface{}{protoKey: h}
}

// ---------------------------------------------------------------------------
// Policy groups
// ---------------------------------------------------------------------------

// buildEgernPolicyGroups converts Clash proxy-groups (with optional proxy-providers)
// to Egern policy_groups. Groups that reference providers via `use:` are converted
// to `external` type; groups with only `proxies:` keep their original type.
func buildEgernPolicyGroups(
	groups []map[string]interface{},
	providersMap map[string]interface{},
	providerOrder []string,
) []map[string]interface{} {
	out := make([]map[string]interface{}, 0)

	// Track which provider names have been consumed by groups
	consumedProviders := map[string]bool{}

	// providerURL returns the URL for a named provider.
	providerURL := func(name string) string {
		if raw, ok := providersMap[name]; ok {
			if cfg, ok := raw.(map[string]interface{}); ok {
				return clash.MapGetStr(cfg, "url", "")
			}
		}
		return ""
	}

	for _, g := range groups {
		name := clash.MapGetStr(g, "name", "")
		gtype := clash.MapGetStr(g, "type", "select")
		proxiesList := clash.ToStringSlice(g["proxies"])
		usesList := clash.ToStringSlice(g["use"])
		filter := clash.MapGetStr(g, "filter", "")
		interval := clash.MapGetInt(g, "interval", 0)
		tolerance := clash.MapGetInt(g, "tolerance", 0)
		timeout := clash.MapGetInt(g, "timeout", 0)

		egernType := clashGroupTypeToEgern(gtype)

		if len(usesList) > 0 && len(proxiesList) == 0 {
			// Pure provider-based group → Egern external
			urls := make([]string, 0, len(usesList))
			for _, u := range usesList {
				if url := providerURL(u); url != "" {
					urls = append(urls, url)
					consumedProviders[u] = true
				}
			}
			ext := map[string]interface{}{
				"name": name,
				"type": egernType,
				"urls": urls,
			}
			if filter != "" {
				ext["filter"] = filter
			}
			if interval > 0 {
				ext["interval"] = interval
			}
			if tolerance > 0 {
				ext["tolerance"] = tolerance
			}
			if timeout > 0 {
				ext["timeout"] = timeout
			}
			out = append(out, map[string]interface{}{"external": ext})

		} else if len(usesList) > 0 && len(proxiesList) > 0 {
			// Mixed: create helper external sub-groups for providers, then main group
			subGroupNames := make([]string, 0, len(usesList))
			for _, u := range usesList {
				if url := providerURL(u); url != "" {
					subName := name + "_" + u
					subFilter := filter
					subExt := map[string]interface{}{
						"name": subName,
						"type": egernType,
						"urls": []string{url},
					}
					if subFilter != "" {
						subExt["filter"] = subFilter
					}
					out = append(out, map[string]interface{}{"external": subExt})
					subGroupNames = append(subGroupNames, subName)
					consumedProviders[u] = true
				}
			}
			// Main group with proxy names + sub-group names
			policies := append(proxiesList, subGroupNames...)
			grp := buildEgernGroupEntry(egernType, name, policies, interval, tolerance, timeout, filter)
			out = append(out, grp)

		} else {
			// Pure proxies group
			grp := buildEgernGroupEntry(egernType, name, proxiesList, interval, tolerance, timeout, filter)
			out = append(out, grp)
		}
	}

	// Add standalone external groups for unused providers
	for _, pname := range providerOrder {
		if consumedProviders[pname] {
			continue
		}
		raw, ok := providersMap[pname]
		if !ok {
			continue
		}
		cfg, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		url := clash.MapGetStr(cfg, "url", "")
		if url == "" {
			continue
		}
		ext := map[string]interface{}{
			"name": pname,
			"type": "select",
			"urls": []string{url},
		}
		if ef := clash.MapGetStr(cfg, "filter", ""); ef != "" {
			ext["filter"] = ef
		}
		out = append(out, map[string]interface{}{"external": ext})
	}

	return out
}

func clashGroupTypeToEgern(gtype string) string {
	switch gtype {
	case "url-test":
		return "auto_test"
	case "load-balance":
		return "load_balance"
	case "fallback":
		return "fallback"
	default:
		return "select"
	}
}

func buildEgernGroupEntry(
	egernType, name string,
	policies []string,
	interval, tolerance, timeout int,
	filter string,
) map[string]interface{} {
	grp := map[string]interface{}{
		"name":     name,
		"policies": policies,
	}
	if filter != "" {
		grp["filter"] = filter
	}
	switch egernType {
	case "auto_test":
		if interval > 0 {
			grp["interval"] = interval
		}
		if tolerance > 0 {
			grp["tolerance"] = tolerance
		}
		if timeout > 0 {
			grp["timeout"] = timeout
		}
	case "fallback":
		if interval > 0 {
			grp["interval"] = interval
		}
		if timeout > 0 {
			grp["timeout"] = timeout
		}
	}
	return map[string]interface{}{egernType: grp}
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

func buildEgernRules(
	rules []interface{},
	ruleProviders map[string]interface{},
	ruleProviderOrder []string,
) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(rules))

	providerURLs := map[string]string{}
	for rpName, rpCfgRaw := range ruleProviders {
		if rpCfg, ok := rpCfgRaw.(map[string]interface{}); ok {
			providerURLs[rpName] = clash.MapGetStr(rpCfg, "url", "")
		}
	}

	for _, ruleRaw := range rules {
		if ruleRaw == nil {
			continue
		}
		ruleStr := strings.TrimSpace(fmt.Sprintf("%v", ruleRaw))
		if ruleStr == "" || strings.HasPrefix(ruleStr, "#") {
			continue
		}

		parts := make([]string, 0)
		for _, pt := range strings.Split(ruleStr, ",") {
			parts = append(parts, strings.TrimSpace(pt))
		}
		if len(parts) < 2 {
			continue
		}

		ruleType := strings.ToUpper(parts[0])
		match := parts[1]
		policy := ""
		if len(parts) > 2 {
			policy = parts[2]
		}

		entry := convertRuleToEgern(ruleType, match, policy, providerURLs)
		if entry != nil {
			out = append(out, entry)
		}
	}

	return out
}

func convertRuleToEgern(ruleType, match, policy string, providerURLs map[string]string) map[string]interface{} {
	inner := func(egernType string, extra ...map[string]interface{}) map[string]interface{} {
		m := map[string]interface{}{
			"match":  match,
			"policy": policy,
		}
		for _, e := range extra {
			for k, v := range e {
				m[k] = v
			}
		}
		return map[string]interface{}{egernType: m}
	}

	switch ruleType {
	case "DOMAIN":
		return inner("domain")
	case "DOMAIN-SUFFIX":
		return inner("domain_suffix")
	case "DOMAIN-KEYWORD":
		return inner("domain_keyword")
	case "DOMAIN-REGEX":
		return inner("domain_regex")
	case "DOMAIN-WILDCARD":
		return inner("domain_wildcard")
	case "GEOIP":
		noResolve := false
		if policy == "" && match != "" {
			// Sometimes policy is the 3rd field; GEOIP might have no-resolve as extra flag
		}
		m := map[string]interface{}{
			"match":  match,
			"policy": policy,
		}
		if noResolve {
			m["no_resolve"] = true
		}
		return map[string]interface{}{"geoip": m}
	case "IP-CIDR", "IP-CIDR6":
		egType := "ip_cidr"
		if ruleType == "IP-CIDR6" {
			egType = "ip_cidr6"
		}
		return inner(egType)
	case "IP-ASN", "ASN":
		return inner("asn")
	case "URL-REGEX":
		return inner("url_regex")
	case "DST-PORT", "DEST-PORT":
		return inner("dest_port")
	case "SRC-PORT":
		return inner("dest_port") // approximate mapping
	case "NETWORK":
		return inner("protocol")
	case "PROCESS-NAME":
		// Not supported in Egern; skip
		return nil
	case "RULE-SET":
		rpName := match
		url := providerURLs[rpName]
		if url == "" {
			return nil
		}
		return map[string]interface{}{
			"rule_set": map[string]interface{}{
				"match":  url,
				"policy": policy,
			},
		}
	case "MATCH", "FINAL":
		return map[string]interface{}{
			"default": map[string]interface{}{
				"policy": policy,
			},
		}
	default:
		// Unknown rule type — skip
		return nil
	}
}
