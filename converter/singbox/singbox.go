// Package singbox converts a Clash (mihomo) YAML config to a sing-box JSON config.
//
// The generated config targets sing-box 1.12 or newer. Clash features that have
// no sing-box equivalent are skipped with an explicit warning; they are never
// silently discarded.
package singbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"clash-nexus/converter"
	"clash-nexus/converter/clash"
)

const (
	directTag = "DIRECT"
	rejectTag = "REJECT"
)

// Converter converts Clash YAML to a sing-box JSON config.
type Converter struct {
	// Fetcher is used when ExpandProxyProviders is enabled.
	Fetcher clash.ProviderFetcher
}

// New returns a new sing-box Converter.
func New() *Converter { return &Converter{} }

// NewWithFetcher returns a sing-box Converter that can resolve proxy-providers.
func NewWithFetcher(fetcher clash.ProviderFetcher) *Converter {
	return &Converter{Fetcher: fetcher}
}

// Name returns the short identifier for this converter.
func (c *Converter) Name() string { return "singbox" }

// DefaultExtension returns the file extension for sing-box configs.
func (c *Converter) DefaultExtension() string { return ".json" }

// Convert transforms a Clash config map into a sing-box JSON byte slice.
func (c *Converter) Convert(config map[string]interface{}, root *yaml.Node) ([]byte, []string, error) {
	return c.ConvertWithOptions(config, root, converter.Options{})
}

// ConvertWithOptions transforms a Clash config map into a sing-box JSON byte
// slice, optionally expanding proxy-providers first.
func (c *Converter) ConvertWithOptions(config map[string]interface{}, root *yaml.Node, options converter.Options) ([]byte, []string, error) {
	warnings := []string{}
	if options.ExpandProxyProviders && config["proxy-providers"] != nil {
		expandWarnings, err := clash.ExpandProxyProviders(config, clash.ExpandOptions{
			Fetcher:  c.Fetcher,
			BasePath: options.BasePath,
			RootNode: root,
		})
		if err != nil {
			return nil, nil, err
		}
		warnings = append(warnings, expandWarnings...)
	}

	b := newBuilder(config, root)
	b.build()
	warnings = append(warnings, b.warnings...)
	sort.Strings(warnings)
	warnings = uniqueStrings(warnings)

	content, err := marshalJSON(b.output)
	if err != nil {
		return nil, warnings, err
	}
	return content, warnings, nil
}

func marshalJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// builder accumulates the sing-box documents and the state needed to resolve
// references between them (outbound tags, rule-set tags, DNS tags, ...).
type builder struct {
	config map[string]interface{}
	root   *yaml.Node

	output   map[string]interface{}
	warnings []string

	outbounds    []interface{}
	endpoints    []interface{}
	outboundTags map[string]bool
	proxyTags    []string

	ruleSets     []interface{}
	ruleSetTags  map[string]bool
	ruleSetGeo   map[string]string
	ruleProvider map[string]string

	dnsServers     []interface{}
	dnsTags        map[string]bool
	dnsTagBySpec   map[string]string
	dnsBootstrap   string
	dnsFinal       string
	dnsRealServers []string

	globalFingerprint string
}

func newBuilder(config map[string]interface{}, root *yaml.Node) *builder {
	return &builder{
		config:       config,
		root:         root,
		output:       map[string]interface{}{},
		outboundTags: map[string]bool{directTag: true, rejectTag: true},
		ruleSetTags:  map[string]bool{},
		ruleSetGeo:   map[string]string{},
		ruleProvider: map[string]string{},
		dnsTags:      map[string]bool{},
		dnsTagBySpec: map[string]string{},
	}
}

func (b *builder) build() {
	if log := buildLog(b.config, &b.warnings); log != nil {
		b.output["log"] = log
	}

	if fp := clash.MapGetStr(b.config, "global-client-fingerprint", ""); fp != "" {
		b.globalFingerprint = fp
	}

	b.collectRuleProviders()
	if dns := b.buildDNS(); dns != nil {
		b.output["dns"] = dns
	}
	if inbounds := b.buildInbounds(); len(inbounds) > 0 {
		b.output["inbounds"] = inbounds
	}
	b.buildOutbounds()
	if len(b.endpoints) > 0 {
		b.output["endpoints"] = b.endpoints
	}
	if len(b.outbounds) > 0 {
		b.output["outbounds"] = b.outbounds
	}
	if route := b.buildRoute(); route != nil {
		b.output["route"] = route
	}
	if experimental := b.buildExperimental(); experimental != nil {
		b.output["experimental"] = experimental
	}

	b.warnUnsupportedTopLevel()
}

func buildLog(config map[string]interface{}, warnings *[]string) map[string]interface{} {
	raw := strings.ToLower(strings.TrimSpace(clash.MapGetStr(config, "log-level", "")))
	if raw == "" {
		return nil
	}
	level := raw
	switch raw {
	case "warning":
		level = "warn"
	case "silent":
		level = "error"
	case "trace", "debug", "info", "warn", "error", "fatal", "panic":
	default:
		*warnings = append(*warnings, fmt.Sprintf("unknown log level %q, using info", raw))
		level = "info"
	}
	return map[string]interface{}{"level": level}
}

// ---------------------------------------------------------------------------
// Outbounds and groups
// ---------------------------------------------------------------------------

func (b *builder) buildOutbounds() {
	proxies, _ := b.config["proxies"].([]interface{})
	for _, value := range proxies {
		proxy := clash.AnyMap(value)
		if proxy == nil {
			b.warnf("skipping proxy: expected mapping")
			continue
		}
		if strings.EqualFold(strings.TrimSpace(clash.MapGetStr(proxy, "type", "")), "wireguard") {
			endpoint := b.buildWireGuardEndpoint(proxy)
			if endpoint == nil {
				continue
			}
			tag, _ := endpoint["tag"].(string)
			if tag == "" || b.outboundTags[tag] {
				b.warnf("skipping proxy %q: duplicate or empty tag", tag)
				continue
			}
			b.outboundTags[tag] = true
			b.proxyTags = append(b.proxyTags, tag)
			b.endpoints = append(b.endpoints, endpoint)
			continue
		}
		outbound := b.buildProxy(proxy)
		if outbound == nil {
			continue
		}
		tag, _ := outbound["tag"].(string)
		if tag == "" || b.outboundTags[tag] {
			b.warnf("skipping proxy %q: duplicate or empty tag", tag)
			continue
		}
		b.outboundTags[tag] = true
		b.proxyTags = append(b.proxyTags, tag)
		b.outbounds = append(b.outbounds, outbound)
	}

	b.buildGroups()

	if !b.hasOutbound(directTag) {
		b.outbounds = append(b.outbounds, map[string]interface{}{"type": "direct", "tag": directTag})
	}
	if !b.hasOutbound(rejectTag) {
		b.outbounds = append(b.outbounds, map[string]interface{}{"type": "block", "tag": rejectTag})
	}

	b.validateDetours()
}

func (b *builder) hasOutbound(tag string) bool {
	for _, value := range b.outbounds {
		if outbound, ok := value.(map[string]interface{}); ok {
			if outbound["tag"] == tag {
				return true
			}
		}
	}
	return false
}

func (b *builder) validateDetours() {
	for _, value := range append(append([]interface{}{}, b.outbounds...), b.endpoints...) {
		outbound, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		detour, _ := outbound["detour"].(string)
		if detour == "" || b.outboundTags[detour] {
			continue
		}
		delete(outbound, "detour")
		b.warnf("removed dialer-proxy %q from outbound %q: no such outbound", detour, outbound["tag"])
	}
}

// buildGroups converts Clash proxy-groups to selector/urltest outbounds. Groups
// are emitted after proxies so that members can be resolved deterministically.
func (b *builder) buildGroups() {
	rawGroups, _ := b.config["proxy-groups"].([]interface{})
	type pendingGroup struct {
		group map[string]interface{}
		name  string
		typ   string
	}
	pending := make([]pendingGroup, 0, len(rawGroups))
	pendingNames := map[string]bool{}

	for _, value := range rawGroups {
		group := clash.AnyMap(value)
		if group == nil {
			b.warnf("skipping proxy group: expected mapping")
			continue
		}
		name := strings.TrimSpace(clash.MapGetStr(group, "name", ""))
		if name == "" {
			b.warnf("skipping proxy group: missing name")
			continue
		}
		if b.outboundTags[name] || pendingNames[name] {
			b.warnf("skipping proxy group %q: duplicate tag", name)
			continue
		}
		pendingNames[name] = true
		pending = append(pending, pendingGroup{group: group, name: name, typ: strings.ToLower(clash.MapGetStr(group, "type", "select"))})
	}

	available := map[string]bool{directTag: true, rejectTag: true}
	for _, tag := range b.proxyTags {
		available[tag] = true
	}
	built := map[string]bool{}

	for {
		progress := false
		remaining := pending[:0]
		for _, item := range pending {
			members, unresolved := b.resolveGroupMembers(item.group, item.name, available, pendingNames, built)
			if unresolved > 0 {
				remaining = append(remaining, item)
				continue
			}
			if len(members) == 0 {
				b.warnf("skipping proxy group %q: no outbounds available after conversion", item.name)
				built[item.name] = false
				pendingNames[item.name] = false
				progress = true
				continue
			}
			if b.buildGroupOutbound(item.name, item.typ, item.group, members) {
				built[item.name] = true
				available[item.name] = true
				b.outboundTags[item.name] = true
				pendingNames[item.name] = false
				progress = true
			} else {
				built[item.name] = false
				pendingNames[item.name] = false
				progress = true
			}
		}
		pending = remaining
		if !progress || len(pending) == 0 {
			break
		}
	}

	for _, item := range pending {
		members, _ := b.resolveGroupMembers(item.group, item.name, available, pendingNames, built)
		if len(members) == 0 {
			b.warnf("skipping proxy group %q: no resolvable outbounds (possible dependency cycle)", item.name)
			continue
		}
		if b.buildGroupOutbound(item.name, item.typ, item.group, members) {
			available[item.name] = true
			b.outboundTags[item.name] = true
		}
	}
}

func (b *builder) resolveGroupMembers(group map[string]interface{}, groupName string, available, pendingNames, built map[string]bool) ([]string, int) {
	members := make([]string, 0)
	seen := map[string]bool{}
	unresolved := 0
	for _, raw := range clash.ToStringSlice(group["proxies"]) {
		member := strings.TrimSpace(raw)
		if member == "" {
			continue
		}
		if member == "GLOBAL" {
			for _, tag := range b.proxyTags {
				if !seen[tag] {
					seen[tag] = true
					members = append(members, tag)
				}
			}
			continue
		}
		member = normalizePolicy(member)
		if member == "" {
			b.warnf("proxy group %q: dropping PASS member, which has no sing-box equivalent", groupName)
			continue
		}
		if available[member] {
			if !seen[member] {
				seen[member] = true
				members = append(members, member)
			}
			continue
		}
		if pendingNames[member] && !built[member] {
			unresolved++
			continue
		}
		b.warnf("proxy group %q: dropping unknown outbound %q", groupName, member)
	}

	if uses := clash.ToStringSlice(group["use"]); len(uses) > 0 {
		for _, provider := range uses {
			b.warnf("proxy group %q: proxy-provider %q is not supported by sing-box; use -expand-proxy-providers to inline it", groupName, provider)
		}
	}
	for _, key := range []string{"include-all", "include-all-proxies", "include-all-providers"} {
		if !clash.MapGetBool(group, key, false) {
			continue
		}
		// include-all-proxies has a direct equivalent: append every proxy.
		if key == "include-all-proxies" {
			for _, tag := range b.proxyTags {
				if !seen[tag] {
					seen[tag] = true
					members = append(members, tag)
				}
			}
			continue
		}
		b.warnf("proxy group %q: %s is not supported by sing-box", groupName, key)
	}
	return members, unresolved
}

func (b *builder) buildGroupOutbound(name, groupType string, group map[string]interface{}, members []string) bool {
	outboundType := "selector"
	switch groupType {
	case "select":
	case "url-test":
		outboundType = "urltest"
	case "fallback":
		outboundType = "urltest"
		b.warnf("proxy group %q: fallback is mapped to urltest", name)
	case "load-balance":
		b.warnf("proxy group %q: load-balance is mapped to selector", name)
	case "relay":
		b.warnf("proxy group %q: relay is mapped to selector", name)
	default:
		b.warnf("proxy group %q: unknown type %q is mapped to selector", name, groupType)
	}

	outbound := map[string]interface{}{
		"type":      outboundType,
		"tag":       name,
		"outbounds": members,
	}
	if outboundType == "urltest" {
		if url := strings.TrimSpace(clash.MapGetStr(group, "url", "")); url != "" {
			outbound["url"] = url
		}
		if interval := mapInt(group, "interval", 0); interval > 0 {
			outbound["interval"] = durationSeconds(interval)
		}
		if tolerance := mapInt(group, "tolerance", 0); tolerance > 0 {
			outbound["tolerance"] = tolerance
		}
	} else if interval := mapInt(group, "interval", 0); interval > 0 {
		b.warnf("proxy group %q: selector does not support interval, ignored", name)
	}

	b.outbounds = append(b.outbounds, outbound)
	return true
}

// ---------------------------------------------------------------------------
// Rule providers and rule sets
// ---------------------------------------------------------------------------

func (b *builder) collectRuleProviders() {
	providers := clash.AnyMap(b.config["rule-providers"])
	if len(providers) == 0 {
		return
	}
	order := clash.OrderedKeysFromNode(b.root, "rule-providers")
	if len(order) == 0 {
		order = sortedKeys(providers)
	}
	for _, name := range order {
		raw, exists := providers[name]
		if !exists {
			continue
		}
		cfg := clash.AnyMap(raw)
		if cfg == nil {
			b.warnf("skipping rule provider %q: expected mapping", name)
			continue
		}
		rawURL := strings.TrimSpace(clash.MapGetStr(cfg, "url", ""))
		path := strings.TrimSpace(clash.MapGetStr(cfg, "path", ""))
		format, ok := ruleProviderFormat(rawURL, path, clash.MapGetStr(cfg, "format", ""))
		if !ok {
			b.warnf("skipping rule provider %q: sing-box cannot load Clash rule-set format; RULE-SET rules using it will be skipped", name)
			continue
		}
		tag := b.uniqueRuleSetTag(name)
		providerType := strings.ToLower(strings.TrimSpace(clash.MapGetStr(cfg, "type", "http")))
		def := map[string]interface{}{"tag": tag, "format": format}
		if providerType == "file" || rawURL == "" {
			if path == "" {
				b.warnf("skipping rule provider %q: missing path", name)
				continue
			}
			def["type"] = "local"
			def["path"] = path
		} else {
			def["type"] = "remote"
			def["url"] = rawURL
			if interval := mapInt(cfg, "interval", 0); interval > 0 {
				def["update_interval"] = durationSeconds(interval)
			}
		}
		b.ruleProvider[name] = tag
		b.addRuleSet(def)
	}
}

func ruleProviderFormat(rawURL, path, declared string) (string, bool) {
	candidate := rawURL
	if candidate == "" {
		candidate = path
	}
	base := strings.ToLower(candidate)
	if idx := strings.IndexAny(base, "?#"); idx >= 0 {
		base = base[:idx]
	}
	switch {
	case strings.HasSuffix(base, ".srs"):
		return "binary", true
	case strings.HasSuffix(base, ".json"):
		return "source", true
	case strings.HasSuffix(base, ".yaml"), strings.HasSuffix(base, ".yml"), strings.HasSuffix(base, ".list"), strings.HasSuffix(base, ".txt"):
		return "", false
	}
	switch strings.ToLower(strings.TrimSpace(declared)) {
	case "binary":
		return "binary", true
	case "json", "source":
		return "source", true
	}
	return "", false
}

func (b *builder) uniqueRuleSetTag(base string) string {
	base = sanitizeTag(base)
	if base == "" {
		base = "rule-set"
	}
	tag := base
	for i := 2; b.ruleSetTags[tag]; i++ {
		tag = fmt.Sprintf("%s-%d", base, i)
	}
	b.ruleSetTags[tag] = true
	return tag
}

func (b *builder) addRuleSet(def map[string]interface{}) {
	b.ruleSets = append(b.ruleSets, def)
}

func (b *builder) ensureGeoRuleSet(kind, code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" {
		return ""
	}
	key := kind + ":" + code
	if tag, ok := b.ruleSetGeo[key]; ok {
		return tag
	}
	base := sanitizeTag(kind + "-" + code)
	tag := b.uniqueRuleSetTag(base)
	repo := "sing-geosite"
	if kind == "geoip" {
		repo = "sing-geoip"
	}
	b.ruleSetGeo[key] = tag
	b.addRuleSet(map[string]interface{}{
		"type":            "remote",
		"tag":             tag,
		"format":          "binary",
		"url":             fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/%s/rule-set/%s-%s.srs", repo, kind, code),
		"update_interval": "1d",
	})
	return tag
}

// ---------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------

func (b *builder) buildRoute() map[string]interface{} {
	route := map[string]interface{}{}
	rules := make([]interface{}, 0)

	if mode := strings.ToLower(strings.TrimSpace(clash.MapGetStr(b.config, "mode", ""))); mode != "" && mode != "rule" {
		b.warnf("Clash mode %q is not fully reproduced; rules are still converted in rule mode", mode)
	}

	tun := clash.MapGetMap(b.config, "tun")
	if len(tun) > 0 && clash.MapGetBool(tun, "enable", false) && b.output["dns"] != nil {
		rules = append(rules, map[string]interface{}{
			"protocol": "dns",
			"action":   "hijack-dns",
		})
	}

	final := directTag
	for _, value := range toStringSlice(b.config["rules"]) {
		rule := strings.TrimSpace(value)
		if rule == "" || strings.HasPrefix(rule, "#") {
			continue
		}
		ruleType, fields, ok := splitRule(rule)
		if !ok {
			b.warnf("skipping malformed rule %q", rule)
			continue
		}
		if ruleType == "MATCH" || ruleType == "FINAL" {
			if len(fields) == 0 {
				b.warnf("skipping malformed rule %q: missing policy", rule)
				continue
			}
			final = b.resolvePolicy(fields[0], "rule")
			break
		}
		converted := b.convertRule(ruleType, fields)
		if converted != nil {
			rules = append(rules, converted)
		}
	}

	if len(rules) > 0 {
		route["rules"] = rules
	}
	if len(b.ruleSets) > 0 {
		route["rule_set"] = b.ruleSets
	}
	route["final"] = final

	if len(tun) > 0 && clash.MapGetBool(tun, "enable", false) {
		if clash.MapGetBool(tun, "auto-detect-interface", false) {
			route["auto_detect_interface"] = true
		}
	}
	if iface := strings.TrimSpace(clash.MapGetStr(b.config, "interface-name", "")); iface != "" {
		route["default_interface"] = iface
	}
	if mark := routingMark(b.config["routing-mark"]); mark > 0 {
		route["default_mark"] = mark
	}
	if mode := strings.ToLower(strings.TrimSpace(clash.MapGetStr(b.config, "find-process-mode", ""))); mode == "always" {
		route["find_process"] = true
	}
	resolver := b.dnsFinal
	if resolver == "" {
		resolver = b.dnsBootstrap
	}
	if resolver != "" {
		route["default_domain_resolver"] = resolver
	}
	return route
}

func (b *builder) convertRule(ruleType string, fields []string) map[string]interface{} {
	ruleType = strings.ToUpper(strings.TrimSpace(ruleType))
	if len(fields) < 2 {
		b.warnf("skipping rule %s: missing match value or policy", ruleType)
		return nil
	}
	match := strings.TrimSpace(fields[0])
	policy := strings.TrimSpace(fields[1])
	if normalizePolicy(policy) == "" {
		b.warnf("skipping rule %s,%s: PASS has no sing-box equivalent", ruleType, match)
		return nil
	}
	outbound := b.resolvePolicy(policy, "rule")

	rule := map[string]interface{}{}
	switch ruleType {
	case "DOMAIN":
		rule["domain"] = []string{match}
	case "DOMAIN-SUFFIX":
		rule["domain_suffix"] = []string{strings.TrimPrefix(match, ".")}
	case "DOMAIN-KEYWORD":
		rule["domain_keyword"] = []string{match}
	case "DOMAIN-REGEX":
		rule["domain_regex"] = []string{match}
	case "DOMAIN-WILDCARD":
		rule["domain_regex"] = []string{wildcardToRegex(match)}
	case "IP-CIDR", "IP-CIDR6":
		rule["ip_cidr"] = []string{match}
	case "SRC-IP-CIDR":
		rule["source_ip_cidr"] = []string{match}
	case "IP-ASN":
		b.warnf("skipping rule %s,%s: sing-box has no IP-ASN route matcher", ruleType, match)
		return nil
	case "GEOIP":
		if strings.EqualFold(match, "LAN") || strings.EqualFold(match, "PRIVATE") {
			rule["ip_is_private"] = true
		} else {
			tag := b.ensureGeoRuleSet("geoip", match)
			if tag == "" {
				b.warnf("skipping %s,%s: empty geoip code", ruleType, match)
				return nil
			}
			rule["rule_set"] = []string{tag}
		}
	case "GEOSITE":
		tag := b.ensureGeoRuleSet("geosite", match)
		if tag == "" {
			b.warnf("skipping %s,%s: empty geosite code", ruleType, match)
			return nil
		}
		rule["rule_set"] = []string{tag}
	case "RULE-SET":
		tag, ok := b.ruleProvider[match]
		if !ok {
			b.warnf("skipping rule RULE-SET,%s: rule provider is not convertible to a sing-box rule-set", match)
			return nil
		}
		rule["rule_set"] = []string{tag}
	case "DST-PORT", "DEST-PORT":
		applyPortRule(rule, "port", "port_range", match)
	case "SRC-PORT":
		applyPortRule(rule, "source_port", "source_port_range", match)
	case "NETWORK":
		rule["network"] = []string{strings.ToLower(match)}
	case "PROTOCOL":
		b.warnf("skipping rule PROTOCOL,%s: sing-box protocol rules only match sniffed traffic", match)
		return nil
	case "PROCESS-NAME":
		rule["process_name"] = []string{match}
	case "PROCESS-PATH":
		rule["process_path"] = []string{match}
	case "PROCESS-PATH-REGEX":
		rule["process_path_regex"] = []string{match}
	case "URL-REGEX":
		b.warnf("skipping rule %s,%s: sing-box has no URL matcher", ruleType, match)
		return nil
	case "USER-AGENT":
		b.warnf("skipping rule %s,%s: sing-box has no user-agent matcher", ruleType, match)
		return nil
	case "AND", "OR", "NOT":
		logical := b.convertLogicalRule(ruleType, match, fields)
		if logical == nil {
			return nil
		}
		rule = logical
	default:
		b.warnf("skipping unsupported rule type %q (rule: %s)", ruleType, match)
		return nil
	}
	rule["outbound"] = outbound
	return rule
}

func (b *builder) convertLogicalRule(ruleType, match string, fields []string) map[string]interface{} {
	// Clash logical rules look like: AND,((DOMAIN,a),(NETWORK,tcp)),POLICY
	// splitRule gives us the parenthesised expression as match; the policy is
	// the last field.
	if len(fields) < 2 {
		b.warnf("skipping malformed logical rule %s,%s", ruleType, match)
		return nil
	}
	expression := match
	policy := fields[len(fields)-1]
	subRules := splitLogicalOperands(expression)
	if len(subRules) == 0 {
		b.warnf("skipping malformed logical rule %s,%s", ruleType, match)
		return nil
	}
	converted := make([]interface{}, 0, len(subRules))
	for _, sub := range subRules {
		subType, subFields, ok := splitRule(sub)
		if !ok || len(subFields) < 1 {
			b.warnf("skipping malformed logical sub-rule %q", sub)
			return nil
		}
		if len(subFields) == 1 {
			subFields = append(subFields, "DIRECT")
		}
		child := b.convertRule(subType, subFields)
		if child == nil {
			return nil
		}
		delete(child, "outbound")
		converted = append(converted, child)
	}
	return map[string]interface{}{
		"type":     "logical",
		"mode":     strings.ToLower(ruleType),
		"rules":    converted,
		"outbound": b.resolvePolicy(policy, "rule"),
	}
}

func splitLogicalOperands(expression string) []string {
	expression = strings.TrimSpace(expression)
	expression = strings.TrimPrefix(expression, "(")
	expression = strings.TrimSuffix(expression, ")")
	parts := []string{}
	depth := 0
	start := 0
	for i, r := range expression {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				part := strings.TrimSpace(expression[start:i])
				part = strings.TrimPrefix(part, "(")
				part = strings.TrimSuffix(part, ")")
				if part != "" {
					parts = append(parts, part)
				}
				start = i + 1
			}
		}
	}
	part := strings.TrimSpace(expression[start:])
	part = strings.TrimPrefix(part, "(")
	part = strings.TrimSuffix(part, ")")
	if part != "" {
		parts = append(parts, part)
	}
	return parts
}

func applyPortRule(rule map[string]interface{}, portKey, rangeKey, value string) {
	if strings.Contains(value, "-") {
		rule[rangeKey] = []string{strings.ReplaceAll(value, "-", ":")}
		return
	}
	if port, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
		rule[portKey] = []int{port}
	}
}

// splitRule splits a Clash rule at top-level commas. Parenthesised expressions
// (logical rules) keep their inner commas intact.
func splitRule(rule string) (string, []string, bool) {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return "", nil, false
	}
	fields := []string{}
	depth := 0
	start := 0
	for i, r := range rule {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return "", nil, false
			}
		case ',':
			if depth == 0 {
				fields = append(fields, strings.TrimSpace(rule[start:i]))
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return "", nil, false
	}
	fields = append(fields, strings.TrimSpace(rule[start:]))
	if len(fields) < 2 {
		return "", nil, false
	}
	ruleType := strings.ToUpper(strings.TrimSpace(fields[0]))
	return ruleType, fields[1:], true
}

func (b *builder) resolvePolicy(policy, context string) string {
	policy = normalizePolicy(policy)
	if policy == "" {
		return directTag
	}
	if policy == directTag || policy == rejectTag {
		return policy
	}
	if b.outboundTags[policy] {
		return policy
	}
	b.warnf("%s: policy %q has no matching outbound, using DIRECT", context, policy)
	return directTag
}

func normalizePolicy(policy string) string {
	policy = strings.TrimSpace(policy)
	switch strings.ToUpper(policy) {
	case "DIRECT":
		return directTag
	case "REJECT", "REJECT-DROP":
		return rejectTag
	case "PASS":
		return ""
	default:
		return policy
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (b *builder) warnf(format string, args ...interface{}) {
	b.warnings = append(b.warnings, fmt.Sprintf(format, args...))
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func sanitizeTag(raw string) string {
	raw = strings.TrimSpace(raw)
	var out strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out.WriteRune(r)
		default:
			out.WriteRune('-')
		}
	}
	return strings.Trim(out.String(), "-")
}

func toStringSlice(v interface{}) []string {
	switch value := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(value))
		for _, item := range value {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	case []string:
		return value
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		return []string{value}
	default:
		return nil
	}
}

func mapInt(m map[string]interface{}, key string, def int) int {
	value, ok := m[key]
	if !ok {
		return def
	}
	switch n := value.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return parsed
		}
	}
	return def
}

func routingMark(v interface{}) uint32 {
	switch value := v.(type) {
	case int:
		if value > 0 {
			return uint32(value)
		}
	case int64:
		if value > 0 {
			return uint32(value)
		}
	case string:
		parsed, err := strconv.ParseUint(strings.TrimSpace(value), 0, 32)
		if err == nil {
			return uint32(parsed)
		}
	}
	return 0
}

func durationSeconds(seconds int) string {
	if seconds <= 0 {
		return ""
	}
	duration := time.Duration(seconds) * time.Second
	if seconds%3600 == 0 {
		return fmt.Sprintf("%dh", seconds/3600)
	}
	if seconds%60 == 0 {
		return fmt.Sprintf("%dm", seconds/60)
	}
	return duration.String()
}

func wildcardToRegex(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	if !strings.ContainsAny(pattern, "*?") {
		return "^" + regexpQuote(pattern) + "$"
	}
	var out strings.Builder
	out.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			out.WriteString(".*")
		case '?':
			out.WriteString(".")
		default:
			out.WriteString(regexpQuote(string(r)))
		}
	}
	out.WriteString("$")
	return out.String()
}

func regexpQuote(s string) string {
	return regexp.QuoteMeta(s)
}

func isIP(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

// warnUnsupportedTopLevel reports Clash fields that are intentionally not
// represented in the output. Keys handled by the builders above are ignored.
func (b *builder) warnUnsupportedTopLevel() {
	handled := map[string]bool{
		"log-level": true, "mode": true, "ipv6": true, "allow-lan": true,
		"bind-address": true, "authentication": true,
		"port": true, "socks-port": true, "mixed-port": true, "redir-port": true, "tproxy-port": true,
		"tun": true, "dns": true, "hosts": true,
		"proxies": true, "proxy-groups": true, "proxy-providers": true,
		"rule-providers": true, "rules": true,
		"external-controller": true, "secret": true, "external-ui": true, "external-ui-url": true,
		"interface-name": true, "routing-mark": true, "global-client-fingerprint": true,
		"find-process-mode": true,
	}
	for _, key := range sortedKeys(b.config) {
		if handled[key] {
			continue
		}
		switch key {
		case "sniffer":
			b.warnf("ignored Clash field %q: sing-box handles protocol sniffing with route rules", key)
		case "experimental":
			b.warnf("ignored Clash field %q: only external-controller/secret/external-ui are mapped", key)
		case "profile":
			b.warnf("ignored Clash field %q: sing-box keeps selections in its own cache", key)
		case "tcp-concurrent", "unified-delay", "keep-alive-interval", "keep-alive-idle",
			"geodata-mode", "geo-auto-update", "geox-url":
			b.warnf("ignored Clash field %q: no sing-box equivalent", key)
		default:
			b.warnf("ignored unsupported Clash field %q", key)
		}
	}
	if _, exists := b.config["proxy-providers"]; exists {
		b.warnf("proxy-providers are not natively supported by sing-box; use -expand-proxy-providers to inline them")
	}
}
