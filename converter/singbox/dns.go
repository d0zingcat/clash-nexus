package singbox

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"clash-nexus/converter/clash"
)

func (b *builder) buildDNS() map[string]interface{} {
	dnsCfg := clash.MapGetMap(b.config, "dns")
	hosts := clash.MapGetMap(b.config, "hosts")
	if len(dnsCfg) == 0 && len(hosts) == 0 {
		return nil
	}
	if len(dnsCfg) > 0 && dnsCfg["enable"] != nil && !clash.MapGetBool(dnsCfg, "enable", true) {
		if len(hosts) == 0 {
			b.warnf("dns is disabled in the Clash config; no dns section generated")
			return nil
		}
		b.warnf("dns.enable is false; hosts entries are still converted")
	}

	rules := make([]interface{}, 0)

	if len(hosts) > 0 {
		if tag, hostRules := b.addHostsServer(hosts); tag != "" {
			rules = append(rules, hostRules...)
		}
	}

	for _, raw := range toStringSlice(dnsCfg["default-nameserver"]) {
		b.addDNSServer(raw, "bootstrap", true)
	}
	for _, raw := range toStringSlice(dnsCfg["nameserver"]) {
		b.addDNSServer(raw, "dns", false)
	}
	for _, raw := range toStringSlice(dnsCfg["fallback"]) {
		b.addDNSServer(raw, "dns", false)
	}
	for _, key := range []string{"proxy-server-nameserver", "direct-nameserver"} {
		values := toStringSlice(dnsCfg[key])
		if len(values) == 0 {
			continue
		}
		b.warnf("dns.%s is Clash-specific; its servers are added to dns.servers without a dedicated routing rule", key)
		for _, raw := range values {
			b.addDNSServer(raw, "dns", false)
		}
	}

	b.resolveDNSDomainResolvers()

	if len(b.dnsServers) == 0 {
		b.addLocalDNSServer()
	}

	if policy := clash.MapGetMap(dnsCfg, "nameserver-policy"); len(policy) > 0 {
		for _, pattern := range sortedKeys(policy) {
			value := policy[pattern]
			serverTag := b.dnsTagForPolicy(value, "dns.nameserver-policy")
			if serverTag == "" {
				continue
			}
			matcher := b.domainMatcher(pattern, "dns.nameserver-policy")
			if len(matcher) == 0 {
				continue
			}
			matcher["server"] = serverTag
			rules = append(rules, matcher)
		}
	}

	if strings.EqualFold(strings.TrimSpace(clash.MapGetStr(dnsCfg, "enhanced-mode", "")), "fake-ip") {
		fakeipRules, fakeipTag := b.buildFakeIP(dnsCfg)
		if fakeipTag != "" {
			rules = append(rules, fakeipRules...)
			rules = append(rules, map[string]interface{}{
				"query_type": []string{"A", "AAAA"},
				"server":     fakeipTag,
			})
		}
	}

	if len(b.dnsRealServers) == 0 && b.dnsBootstrap == "" {
		b.addLocalDNSServer()
	}
	if b.dnsFinal == "" {
		if len(b.dnsRealServers) > 0 {
			b.dnsFinal = b.dnsRealServers[0]
		} else if b.dnsBootstrap != "" {
			b.dnsFinal = b.dnsBootstrap
		}
	}

	dns := map[string]interface{}{
		"servers": b.dnsServers,
	}
	if len(rules) > 0 {
		dns["rules"] = rules
	}
	if b.dnsFinal != "" {
		dns["final"] = b.dnsFinal
	}
	if !clash.MapGetBool(b.config, "ipv6", false) {
		dns["strategy"] = "ipv4_only"
	}
	return dns
}

func (b *builder) addHostsServer(hosts map[string]interface{}) (string, []interface{}) {
	predefined := map[string]interface{}{}
	domains := []string{}
	rules := []interface{}{}
	for _, key := range sortedKeys(hosts) {
		host := strings.TrimSpace(key)
		value := hosts[key]
		switch {
		case strings.HasPrefix(host, "*."):
			b.warnf("hosts entry %q: wildcard hosts are not supported by sing-box, entry skipped", host)
			continue
		case strings.HasPrefix(host, "+."):
			b.warnf("hosts entry %q: wildcard hosts are not supported by sing-box, entry skipped", host)
			continue
		}
		if host == "" {
			continue
		}
		switch v := value.(type) {
		case []interface{}:
			values := make([]string, 0, len(v))
			for _, item := range v {
				values = append(values, fmt.Sprintf("%v", item))
			}
			predefined[host] = values
		case []string:
			predefined[host] = v
		default:
			predefined[host] = fmt.Sprintf("%v", v)
		}
		domains = append(domains, host)
	}
	if len(predefined) == 0 {
		return "", nil
	}
	tag := "hosts"
	if b.dnsTags[tag] {
		tag = b.uniqueDNSChildTag("hosts")
	}
	b.dnsTags[tag] = true
	b.dnsServers = append([]interface{}{map[string]interface{}{
		"type":       "hosts",
		"tag":        tag,
		"predefined": predefined,
	}}, b.dnsServers...)
	if len(domains) > 0 {
		rules = append(rules, map[string]interface{}{
			"domain": domains,
			"server": tag,
		})
	}
	return tag, rules
}

// addDNSServer parses a Clash nameserver string and appends a type-based
// sing-box DNS server. The first bootstrap server is remembered so hostname
// upstreams can use it in their domain_resolver field.
func (b *builder) addDNSServer(raw, prefix string, bootstrap bool) string {
	raw = strings.Trim(strings.TrimSpace(raw), `"'`)
	if raw == "" {
		return ""
	}
	if tag, ok := b.dnsTagBySpec[raw]; ok {
		if bootstrap && b.dnsBootstrap == "" {
			b.dnsBootstrap = tag
		}
		return tag
	}
	def, host, err := parseDNSAddress(raw)
	if err != nil {
		b.warnf("skipping DNS server %q: %v", raw, err)
		return ""
	}
	tag := b.uniqueDNSChildTag(prefix)
	def["tag"] = tag
	b.dnsServers = append(b.dnsServers, def)
	b.dnsTags[tag] = true
	b.dnsTagBySpec[raw] = tag
	if host != "" && !isIP(host) {
		// Filled in by resolveDNSDomainResolvers once bootstrap is known.
		def["_domain_resolver_host"] = host
	}
	if bootstrap {
		if b.dnsBootstrap == "" {
			b.dnsBootstrap = tag
		}
	} else {
		b.dnsRealServers = append(b.dnsRealServers, tag)
		if b.dnsFinal == "" {
			b.dnsFinal = tag
		}
	}
	return tag
}

func (b *builder) uniqueDNSChildTag(prefix string) string {
	if prefix == "" {
		prefix = "dns"
	}
	tag := prefix
	if !b.dnsTags[tag] {
		return tag
	}
	for i := 2; ; i++ {
		tag = fmt.Sprintf("%s-%d", prefix, i)
		if !b.dnsTags[tag] {
			return tag
		}
	}
}

func (b *builder) addLocalDNSServer() string {
	if tag, ok := b.dnsTagBySpec["local"]; ok {
		return tag
	}
	tag := b.uniqueDNSChildTag("local")
	b.dnsServers = append(b.dnsServers, map[string]interface{}{"type": "local", "tag": tag})
	b.dnsTags[tag] = true
	b.dnsTagBySpec["local"] = tag
	b.dnsTagBySpec["system"] = tag
	if b.dnsBootstrap == "" {
		b.dnsBootstrap = tag
	}
	return tag
}

func (b *builder) resolveDNSDomainResolvers() {
	for _, value := range b.dnsServers {
		server, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		host, _ := server["_domain_resolver_host"].(string)
		delete(server, "_domain_resolver_host")
		if host == "" {
			continue
		}
		tag, _ := server["tag"].(string)
		resolver := b.dnsBootstrap
		if resolver == "" || resolver == tag {
			resolver = b.addLocalDNSServer()
			if resolver == tag {
				b.warnf("DNS server %q cannot be used as its own domain resolver", tag)
				continue
			}
		}
		server["domain_resolver"] = resolver
	}
}

func (b *builder) dnsTagForPolicy(value interface{}, context string) string {
	raw := ""
	switch v := value.(type) {
	case []interface{}:
		if len(v) > 1 {
			b.warnf("%s: multiple DNS servers for one policy, only the first is used", context)
		}
		if len(v) > 0 {
			raw = strings.TrimSpace(fmt.Sprintf("%v", v[0]))
		}
	case []string:
		if len(v) > 1 {
			b.warnf("%s: multiple DNS servers for one policy, only the first is used", context)
		}
		if len(v) > 0 {
			raw = strings.TrimSpace(v[0])
		}
	default:
		raw = strings.TrimSpace(fmt.Sprintf("%v", value))
	}
	raw = strings.Trim(raw, `"'`)
	if raw == "" || raw == "<nil>" {
		return ""
	}
	if tag, ok := b.dnsTagBySpec[raw]; ok {
		return tag
	}
	if raw == "system" || raw == "local" {
		return b.addLocalDNSServer()
	}
	return b.addDNSServer(raw, "dns", false)
}

func (b *builder) domainMatcher(pattern, context string) map[string]interface{} {
	rule := map[string]interface{}{}
	patterns := splitList(pattern)
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		switch {
		case strings.HasPrefix(p, "geosite:"):
			code := strings.TrimSpace(strings.TrimPrefix(p, "geosite:"))
			if tag := b.ensureGeoRuleSet("geosite", code); tag != "" {
				appendStringField(rule, "rule_set", tag)
			}
		case strings.HasPrefix(p, "rule-set:"):
			name := strings.TrimSpace(strings.TrimPrefix(p, "rule-set:"))
			if tag, ok := b.ruleProvider[name]; ok {
				appendStringField(rule, "rule_set", tag)
			} else {
				b.warnf("%s: rule provider %q is not convertible to a sing-box rule-set", context, name)
			}
		case p == "*":
			appendStringField(rule, "domain_regex", ".*")
		case strings.HasPrefix(p, "+."):
			appendStringField(rule, "domain_suffix", strings.TrimPrefix(p, "+."))
		case strings.HasPrefix(p, "."):
			appendStringField(rule, "domain_suffix", strings.TrimPrefix(p, "."))
		case strings.HasPrefix(p, "*."):
			appendStringField(rule, "domain_suffix", strings.TrimPrefix(p, "*."))
		case strings.ContainsAny(p, "*?"):
			appendStringField(rule, "domain_regex", wildcardToRegex(p))
		default:
			appendStringField(rule, "domain", p)
		}
	}
	return rule
}

func (b *builder) buildFakeIP(dnsCfg map[string]interface{}) ([]interface{}, string) {
	filters := toStringSlice(dnsCfg["fake-ip-filter"])
	for _, filter := range filters {
		if strings.TrimSpace(filter) == "*" {
			b.warnf("dns.fake-ip-filter contains \"*\", which disables fake-ip in Clash; fake-ip is not generated")
			return nil, ""
		}
	}

	tag := b.uniqueDNSChildTag("fakeip")
	range4 := strings.TrimSpace(clash.MapGetStr(dnsCfg, "fake-ip-range", ""))
	if range4 == "" {
		range4 = "198.18.0.1/16"
	}
	server := map[string]interface{}{
		"type":        "fakeip",
		"tag":         tag,
		"inet4_range": fakeIPRange(range4),
	}
	if range6 := strings.TrimSpace(clash.MapGetStr(dnsCfg, "fake-ip-range6", "")); range6 != "" {
		server["inet6_range"] = fakeIPRange(range6)
	}
	b.dnsServers = append(b.dnsServers, server)
	b.dnsTags[tag] = true

	rules := []interface{}{}
	if len(filters) > 0 {
		matcher := map[string]interface{}{}
		for _, filter := range filters {
			p := strings.TrimSpace(filter)
			switch {
			case p == "":
				continue
			case strings.HasPrefix(p, "geosite:"):
				code := strings.TrimPrefix(p, "geosite:")
				if setTag := b.ensureGeoRuleSet("geosite", code); setTag != "" {
					appendStringField(matcher, "rule_set", setTag)
				}
			case strings.HasPrefix(p, "rule-set:"):
				name := strings.TrimPrefix(p, "rule-set:")
				if setTag, ok := b.ruleProvider[name]; ok {
					appendStringField(matcher, "rule_set", setTag)
				} else {
					b.warnf("dns.fake-ip-filter: rule provider %q is not convertible to a sing-box rule-set", name)
				}
			case strings.HasPrefix(p, "+."):
				appendStringField(matcher, "domain_suffix", strings.TrimPrefix(p, "+."))
			case strings.HasPrefix(p, "."):
				appendStringField(matcher, "domain_suffix", strings.TrimPrefix(p, "."))
			case strings.HasPrefix(p, "*."):
				appendStringField(matcher, "domain_suffix", strings.TrimPrefix(p, "*."))
			case strings.ContainsAny(p, "*?"):
				appendStringField(matcher, "domain_regex", wildcardToRegex(p))
			default:
				appendStringField(matcher, "domain", p)
			}
		}
		if len(matcher) > 0 {
			realServer := b.dnsFinal
			if realServer == "" && len(b.dnsRealServers) > 0 {
				realServer = b.dnsRealServers[0]
			}
			if realServer == "" {
				realServer = b.addLocalDNSServer()
			}
			matcher["server"] = realServer
			rules = append(rules, matcher)
		}
	}
	return rules, tag
}

func appendStringField(m map[string]interface{}, key, value string) {
	if value == "" {
		return
	}
	switch existing := m[key].(type) {
	case []string:
		m[key] = append(existing, value)
	case nil:
		m[key] = []string{value}
	default:
		m[key] = []string{value}
	}
}

func splitList(raw string) []string {
	return strings.Split(raw, ",")
}

func parseDNSAddress(raw string) (map[string]interface{}, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, "", fmt.Errorf("empty address")
	}
	if raw == "system" || raw == "local" {
		return map[string]interface{}{"type": "local"}, "", nil
	}
	if idx := strings.Index(raw, "#"); idx >= 0 {
		raw = raw[:idx]
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return nil, "", err
		}
		scheme := strings.ToLower(parsed.Scheme)
		host := parsed.Hostname()
		if host == "" {
			return nil, "", fmt.Errorf("missing host")
		}
		switch scheme {
		case "dhcp":
			def := map[string]interface{}{"type": "dhcp"}
			if host != "" && host != "auto" {
				def["interface"] = host
			}
			return def, "", nil
		case "udp", "tcp":
			port := parsePort(parsed.Port(), 53)
			return map[string]interface{}{
				"type":        scheme,
				"server":      host,
				"server_port": port,
			}, host, nil
		case "tls", "quic":
			port := parsePort(parsed.Port(), 853)
			return map[string]interface{}{
				"type":        scheme,
				"server":      host,
				"server_port": port,
			}, host, nil
		case "https", "h3", "http3":
			serverType := "https"
			if scheme == "h3" || scheme == "http3" {
				serverType = "h3"
			}
			port := parsePort(parsed.Port(), 443)
			path := parsed.EscapedPath()
			if path == "" || path == "/" {
				path = "/dns-query"
			}
			return map[string]interface{}{
				"type":        serverType,
				"server":      host,
				"server_port": port,
				"path":        path,
			}, host, nil
		default:
			return nil, "", fmt.Errorf("unsupported DNS scheme %q", scheme)
		}
	}

	host := raw
	port := 53
	if splitHost, splitPort, err := net.SplitHostPort(raw); err == nil {
		host = splitHost
		if parsed, err := strconv.Atoi(splitPort); err == nil {
			port = parsed
		}
	} else if strings.Count(raw, ":") == 1 {
		if idx := strings.LastIndex(raw, ":"); idx > 0 {
			if parsed, err := strconv.Atoi(raw[idx+1:]); err == nil {
				host = raw[:idx]
				port = parsed
			}
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return nil, "", fmt.Errorf("missing host")
	}
	return map[string]interface{}{
		"type":        "udp",
		"server":      host,
		"server_port": port,
	}, host, nil
}

func parsePort(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	if port, err := strconv.Atoi(raw); err == nil && port > 0 {
		return port
	}
	return fallback
}

func fakeIPRange(raw string) string {
	raw = strings.TrimSpace(raw)
	if _, network, err := net.ParseCIDR(raw); err == nil {
		return network.String()
	}
	return raw
}
