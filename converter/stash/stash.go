// Package stash converts a Clash (mihomo) YAML config to a Stash YAML config.
package stash

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Converter converts Clash YAML to Stash YAML format.
type Converter struct{}

// New returns a new Stash Converter.
func New() *Converter { return &Converter{} }

// Name returns the short identifier for this converter.
func (c *Converter) Name() string { return "stash" }

// DefaultExtension returns the file extension for Stash configs.
func (c *Converter) DefaultExtension() string { return ".yaml" }

// Convert transforms a Clash config map into a Stash YAML byte slice.
func (c *Converter) Convert(config map[string]interface{}, _ *yaml.Node) ([]byte, []string, error) {
	warnings := []string{}
	out := buildConfig(config, &warnings)
	content, err := yaml.Marshal(out)
	return content, warnings, err
}

func buildConfig(config map[string]interface{}, warnings *[]string) map[string]interface{} {
	out := make(map[string]interface{})
	for _, key := range sortedKeys(config) {
		value := config[key]
		switch key {
		case "mode", "log-level", "hosts":
			out[key] = value
		case "proxies":
			if proxies, ok := buildProxies(value, warnings); ok {
				out[key] = proxies
			}
		case "proxy-groups":
			if groups, ok := buildProxyGroups(value, warnings); ok {
				out[key] = groups
			}
		case "proxy-providers":
			if providers, ok := buildProviders(value, "proxy provider", stashProxyProviderFields, warnings); ok {
				out[key] = providers
			}
		case "rule-providers":
			if providers, ok := buildProviders(value, "rule provider", stashRuleProviderFields, warnings); ok {
				out[key] = providers
			}
		case "rules":
			if rules, ok := buildRules(value, warnings); ok {
				out[key] = rules
			}
		case "dns":
			if dns, ok := buildDNSConfig(value, warnings); ok {
				out[key] = dns
			}
		default:
			*warnings = append(*warnings, fmt.Sprintf("removed unsupported top-level field %q", key))
		}
	}
	return out
}

func buildDNSConfig(value interface{}, warnings *[]string) (map[string]interface{}, bool) {
	out := make(map[string]interface{})
	dns, ok := value.(map[string]interface{})
	if !ok {
		*warnings = append(*warnings, "dropping dns: expected mapping")
		return nil, false
	}

	for _, key := range sortedKeys(dns) {
		value := dns[key]
		switch key {
		case "default-nameserver", "nameserver", "nameserver-policy",
			"fake-ip-filter", "skip-cert-verify", "follow-rule":
			out[key] = value
		default:
			*warnings = append(*warnings, fmt.Sprintf("removed unsupported dns field %q", key))
		}
	}
	return out, true
}

func buildProxyGroups(value interface{}, warnings *[]string) ([]interface{}, bool) {
	groups, ok := value.([]interface{})
	if !ok {
		*warnings = append(*warnings, "dropping proxy-groups: expected sequence")
		return nil, false
	}

	out := make([]interface{}, 0, len(groups))
	for _, value := range groups {
		group, ok := value.(map[string]interface{})
		if !ok {
			*warnings = append(*warnings, "dropping proxy group: expected mapping")
			continue
		}

		rebuilt := make(map[string]interface{})
		for _, key := range sortedKeys(group) {
			if _, allowed := stashProxyGroupFields[key]; allowed {
				rebuilt[key] = group[key]
				continue
			}
			*warnings = append(*warnings, fmt.Sprintf("removed unsupported proxy group field %q", key))
		}
		out = append(out, rebuilt)
	}
	return out, true
}

func buildProviders(value interface{}, kind string, allowed map[string]struct{}, warnings *[]string) (map[string]interface{}, bool) {
	providers, ok := value.(map[string]interface{})
	if !ok {
		*warnings = append(*warnings, fmt.Sprintf("dropping %ss: expected mapping", kind))
		return nil, false
	}

	out := make(map[string]interface{}, len(providers))
	for _, name := range sortedKeys(providers) {
		provider, ok := providers[name].(map[string]interface{})
		if !ok {
			*warnings = append(*warnings, fmt.Sprintf("dropping %s %q: expected mapping", kind, name))
			continue
		}

		rebuilt := make(map[string]interface{})
		for _, key := range sortedKeys(provider) {
			if _, allowed := allowed[key]; allowed {
				rebuilt[key] = provider[key]
				continue
			}
			*warnings = append(*warnings, fmt.Sprintf(
				"removed unsupported %s field %q from %q", kind, key, name,
			))
		}
		out[name] = rebuilt
	}
	return out, true
}

func buildRules(value interface{}, warnings *[]string) ([]interface{}, bool) {
	rules, ok := value.([]interface{})
	if !ok {
		*warnings = append(*warnings, "dropping rules: expected sequence")
		return nil, false
	}

	out := make([]interface{}, 0, len(rules))
	for _, value := range rules {
		rule, ok := value.(string)
		if !ok {
			*warnings = append(*warnings, "dropping rule: expected string")
			continue
		}
		if strings.TrimSpace(rule) == "" {
			*warnings = append(*warnings, "dropping rule: empty rule")
			continue
		}

		ruleType := strings.TrimSpace(strings.SplitN(rule, ",", 2)[0])
		_, supported := stashRuleTypes[ruleType]
		if strings.HasPrefix(ruleType, "IN-") || !supported {
			*warnings = append(*warnings, fmt.Sprintf(
				"dropping unsupported rule %q: type %q is unsupported by Stash", rule, ruleType,
			))
			continue
		}
		if !hasCompleteRuleSyntax(ruleType, rule) {
			*warnings = append(*warnings, fmt.Sprintf(
				"dropping incomplete rule %q: invalid rule syntax", rule,
			))
			continue
		}
		if ruleType == "PROCESS-NAME" || ruleType == "PROCESS-PATH" {
			*warnings = append(*warnings, fmt.Sprintf(
				"retained process rule %q, but iOS/tvOS ignore it", rule,
			))
		}
		out = append(out, rule)
	}
	return out, true
}

func hasCompleteRuleSyntax(ruleType, rule string) bool {
	coreFields, balanced := splitTopLevelCommaFields(rule)
	if !balanced {
		return false
	}

	modifierCount := 0
	for len(coreFields) > 0 && isRuleModifier(coreFields[len(coreFields)-1]) {
		coreFields = coreFields[:len(coreFields)-1]
		modifierCount++
	}
	for _, field := range coreFields {
		if isRuleModifier(field) {
			return false
		}
	}
	if len(coreFields) == 0 {
		return false
	}
	if ruleType == "MATCH" {
		return modifierCount == 0 &&
			len(coreFields) == 2 &&
			strings.TrimSpace(coreFields[1]) != ""
	}
	if len(coreFields) != 3 {
		return false
	}
	return strings.TrimSpace(coreFields[1]) != "" &&
		strings.TrimSpace(coreFields[2]) != ""
}

func splitTopLevelCommaFields(rule string) ([]string, bool) {
	fields := []string{}
	fieldStart := 0
	depth := 0
	for index, runeValue := range rule {
		switch runeValue {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, false
			}
		case ',':
			if depth == 0 {
				fields = append(fields, rule[fieldStart:index])
				fieldStart = index + 1
			}
		}
	}
	if depth != 0 {
		return nil, false
	}
	return append(fields, rule[fieldStart:]), true
}

func isRuleModifier(field string) bool {
	switch strings.TrimSpace(field) {
	case "no-resolve", "no-track":
		return true
	default:
		return false
	}
}

func buildProxies(value interface{}, warnings *[]string) ([]interface{}, bool) {
	proxies, ok := value.([]interface{})
	if !ok {
		*warnings = append(*warnings, "dropping proxies: expected sequence")
		return nil, false
	}

	out := make([]interface{}, 0, len(proxies))
	for _, value := range proxies {
		proxy, ok := value.(map[string]interface{})
		if !ok {
			*warnings = append(*warnings, "dropping proxy: expected mapping")
			continue
		}
		rebuilt, ok := buildProxy(proxy, warnings)
		if ok {
			out = append(out, rebuilt)
		}
	}
	return out, true
}

func buildProxy(proxy map[string]interface{}, warnings *[]string) (map[string]interface{}, bool) {
	name, nameOK := proxy["name"].(string)
	if !nameOK || name == "" {
		*warnings = append(*warnings, "dropping proxy: missing required string field \"name\"")
		return nil, false
	}
	proxyType, typeOK := proxy["type"].(string)
	if !typeOK || proxyType == "" {
		*warnings = append(*warnings, fmt.Sprintf("dropping proxy %q: missing required string field \"type\"", name))
		return nil, false
	}

	allowed, supported := stashProxyFields[proxyType]
	if !supported {
		*warnings = append(*warnings, fmt.Sprintf("dropping proxy %q: unsupported type %q", name, proxyType))
		return nil, false
	}
	if missingFields := missingRequiredProxyFields(proxy, proxyType); len(missingFields) > 0 {
		*warnings = append(*warnings, fmt.Sprintf(
			"dropping proxy %q: missing or invalid required fields %s",
			name, strings.Join(missingFields, ", "),
		))
		return nil, false
	}

	out := make(map[string]interface{})
	for _, key := range sortedKeys(proxy) {
		if _, ok := allowed[key]; ok {
			out[key] = proxy[key]
			continue
		}
		*warnings = append(*warnings, fmt.Sprintf(
			"removed unsupported proxy field %q from %q (type %q)", key, name, proxyType,
		))
	}
	return out, true
}

func missingRequiredProxyFields(proxy map[string]interface{}, proxyType string) []string {
	missing := []string{}
	if proxyType != "direct" && proxyType != "tailscale" {
		if !hasNonEmptyString(proxy, "server") {
			missing = append(missing, "server")
		}
		if !hasPositiveInt(proxy, "port") {
			missing = append(missing, "port")
		}
	}

	switch proxyType {
	case "ss", "ssr":
		missing = appendMissingStringFields(missing, proxy, "cipher", "password")
	case "vmess", "vless", "tuic", "juicity":
		missing = appendMissingStringFields(missing, proxy, "uuid")
	case "trojan", "anytls":
		missing = appendMissingStringFields(missing, proxy, "password")
	case "hysteria2":
		missing = appendMissingStringFields(missing, proxy, "auth")
	case "snell":
		missing = appendMissingStringFields(missing, proxy, "psk")
	case "hysteria":
		if !hasNonEmptyString(proxy, "auth") && !hasNonEmptyString(proxy, "auth-str") {
			missing = append(missing, "auth or auth-str")
		}
	case "wireguard":
		missing = appendMissingStringFields(missing, proxy, "ip", "private-key", "public-key")
	case "trusttunnel":
		missing = appendMissingStringFields(missing, proxy, "username", "password")
	case "ssh":
		missing = appendMissingStringFields(missing, proxy, "user")
		if !hasNonEmptyString(proxy, "password") && !hasNonEmptyString(proxy, "private-key") {
			missing = append(missing, "password or private-key")
		}
	}
	return missing
}

func appendMissingStringFields(missing []string, proxy map[string]interface{}, fields ...string) []string {
	for _, field := range fields {
		if !hasNonEmptyString(proxy, field) {
			missing = append(missing, field)
		}
	}
	return missing
}

func hasNonEmptyString(proxy map[string]interface{}, field string) bool {
	value, ok := proxy[field].(string)
	return ok && value != ""
}

func hasPositiveInt(proxy map[string]interface{}, field string) bool {
	switch value := proxy[field].(type) {
	case int:
		return value > 0
	case int8:
		return value > 0
	case int16:
		return value > 0
	case int32:
		return value > 0
	case int64:
		return value > 0
	case uint:
		return value > 0
	case uint8:
		return value > 0
	case uint16:
		return value > 0
	case uint32:
		return value > 0
	case uint64:
		return value > 0
	default:
		return false
	}
}

var stashProxyFields = map[string]map[string]struct{}{
	"ss": outboundFieldSet(
		"name", "type", "server", "port", "cipher", "password", "udp",
		"plugin", "plugin-opts", "udp-nameserver",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"ssr": outboundFieldSet(
		"name", "type", "server", "port", "cipher", "password", "obfs",
		"protocol", "obfs-param", "protocol-param",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"socks5": outboundFieldSet(
		"name", "type", "server", "port", "username", "password", "tls",
		"skip-cert-verify", "udp", "udp-nameserver",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"http": outboundFieldSet(
		"name", "type", "server", "port", "headers", "tls", "skip-cert-verify",
		"username", "password",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"vmess": outboundFieldSet(
		"name", "type", "server", "port", "uuid", "cipher", "alterId", "network",
		"tls", "skip-cert-verify", "sni", "servername", "alpn", "ws-opts", "h2-opts",
		"http-opts", "grpc-opts",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"vless": outboundFieldSet(
		"name", "type", "server", "port", "uuid", "flow", "network", "tls",
		"skip-cert-verify", "client-fingerprint", "ws-opts", "grpc-opts",
		"h2-opts", "reality-opts",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"trojan": outboundFieldSet(
		"name", "type", "server", "port", "password", "udp", "sni", "alpn",
		"skip-cert-verify", "network", "ws-opts", "grpc-opts", "udp-nameserver",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"snell": outboundFieldSet(
		"name", "type", "server", "port", "psk", "udp", "version", "obfs-opts",
		"udp-nameserver",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"hysteria": outboundFieldSet(
		"name", "type", "server", "port", "up-speed", "down-speed", "auth-str",
		"auth", "protocol", "obfs", "sni", "alpn", "skip-cert-verify",
		"server-cert-fingerprint", "ports", "hop-interval", "udp-nameserver",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"hysteria2": outboundFieldSet(
		"name", "type", "server", "port", "auth", "fast-open", "obfs",
		"obfs-password", "sni", "skip-cert-verify", "up-speed", "down-speed",
		"ports", "hop-interval", "udp-nameserver",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"tuic": outboundFieldSet(
		"name", "type", "server", "port", "version", "uuid", "password", "token",
		"skip-cert-verify", "sni", "alpn", "ports", "hop-interval",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"juicity": outboundFieldSet(
		"name", "type", "server", "port", "uuid", "password", "skip-cert-verify",
		"sni", "alpn", "ports", "hop-interval",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"wireguard": outboundFieldSet(
		"name", "type", "server", "port", "ip", "ipv6", "private-key",
		"public-key", "preshared-key", "dns", "mtu", "reserved", "keepalive",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"anytls": outboundFieldSet(
		"name", "type", "server", "port", "password",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"trusttunnel": outboundFieldSet(
		"name", "type", "server", "port", "username", "password", "quic", "sni",
		"alpn", "skip-cert-verify", "server-cert-fingerprint",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"tailscale": fieldSet(
		"name", "type", "auth-key", "hostname", "control-url", "ephemeral", "exit-node",
	),
	"ssh": outboundFieldSet(
		"name", "type", "server", "port", "user", "password", "private-key",
		"private-key-passphrase",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
	"direct": fieldSet(
		"name", "type", "interface-name",
		"benchmark-url", "benchmark-timeout", "benchmark-disabled",
	),
}

var stashProxyGroupFields = fieldSet(
	"name", "type", "proxies", "use", "filter", "include-all", "url", "interval",
	"lazy", "strategy", "tolerance", "ssid-policy", "icon",
	"benchmark-url", "benchmark-timeout", "benchmark-disabled",
)

var stashProxyProviderFields = fieldSet(
	"url", "path", "interval", "headers", "filter", "exclude-filter", "health-check",
)

var stashRuleProviderFields = fieldSet(
	"url", "path", "interval", "headers", "filter", "exclude-filter", "health-check",
	"behavior", "format",
)

var stashRuleTypes = fieldSet(
	"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX",
	"GEOIP", "GEOSITE", "IP-ASN", "IP-CIDR", "IP-CIDR6", "NETWORK", "PROTOCOL",
	"DST-PORT", "RULE-SET", "SCRIPT", "AND", "OR", "NOT", "USER-AGENT", "URL-REGEX",
	"PROCESS-NAME", "PROCESS-PATH", "MATCH",
)

func fieldSet(fields ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		set[field] = struct{}{}
	}
	return set
}

func outboundFieldSet(fields ...string) map[string]struct{} {
	return fieldSet(append(fields, "dialer-proxy")...)
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
