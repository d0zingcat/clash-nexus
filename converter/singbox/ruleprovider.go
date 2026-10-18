package singbox

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"clash-nexus/converter/clash"
)

const (
	maxInlineRuleProviderBytes = 5 * 1024 * 1024
	inlineRuleProviderTimeout  = 60 * time.Second
)

// inlineRuleProvider fetches a Clash YAML or Surge .list rule provider and
// converts its payload to a sing-box inline rule-set. sing-box cannot load
// those formats directly, so this keeps RULE-SET rules useful without asking
// the user to rewrite every provider URL.
func (b *builder) inlineRuleProvider(name string, cfg map[string]interface{}) ([]interface{}, error) {
	if b.fetcher == nil {
		return nil, fmt.Errorf("no provider fetcher configured")
	}
	provider := make(map[string]interface{}, len(cfg))
	for key, value := range cfg {
		provider[key] = value
	}
	if strings.TrimSpace(clash.MapGetStr(provider, "type", "")) == "" {
		provider["type"] = "http"
	}

	ctx, cancel := context.WithTimeout(context.Background(), inlineRuleProviderTimeout)
	defer cancel()
	data, err := b.fetcher.Fetch(ctx, provider, b.basePath)
	if err != nil {
		return nil, err
	}
	if len(data) > maxInlineRuleProviderBytes {
		return nil, fmt.Errorf("rule provider exceeds %d MiB", maxInlineRuleProviderBytes/(1024*1024))
	}

	lines, err := parseRuleProviderData(data)
	if err != nil {
		return nil, err
	}
	behavior := strings.ToLower(strings.TrimSpace(clash.MapGetStr(cfg, "behavior", "classical")))
	aggregate := &inlineRules{}
	unsupported := map[string]bool{}
	for _, line := range lines {
		line = cleanRuleProviderLine(line)
		if line == "" {
			continue
		}
		ruleType, fields, ok := parseRuleProviderLine(line, behavior)
		if !ok {
			continue
		}
		switch ruleType {
		case "AND", "OR", "NOT", "GEOIP", "GEOSITE", "RULE-SET", "IP-ASN",
			"URL-REGEX", "USER-AGENT", "PROTOCOL", "DOMAIN-SET", "PROCESS-NAME-REGEX":
			if !unsupported[ruleType] {
				unsupported[ruleType] = true
				b.warnf("rule provider %q: skipping unsupported rule type %q", name, ruleType)
			}
			continue
		}
		matcher := b.convertRuleMatcher(ruleType, fields)
		if matcher == nil {
			continue
		}
		aggregate.add(matcher)
	}
	rules := aggregate.rules()
	if len(rules) == 0 {
		return nil, fmt.Errorf("no supported rules found")
	}
	return rules, nil
}

func parseRuleProviderData(data []byte) ([]string, error) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err == nil && doc != nil {
		for _, key := range []string{"payload", "rules"} {
			if raw, ok := doc[key]; ok {
				return toStringSlice(raw), nil
			}
		}
	}

	var list []interface{}
	if err := yaml.Unmarshal(data, &list); err == nil && len(list) > 0 {
		return toStringSlice(list), nil
	}

	text := strings.TrimPrefix(string(data), "\ufeff")
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, strings.TrimSpace(line))
	}
	return out, nil
}

func cleanRuleProviderLine(line string) string {
	line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") {
		return ""
	}
	for _, marker := range []string{" #", " //"} {
		if idx := strings.Index(line, marker); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
	}
	return strings.TrimSpace(line)
}

func parseRuleProviderLine(line, behavior string) (string, []string, bool) {
	if strings.Contains(line, ",") {
		ruleType, fields, ok := splitRule(line)
		if ok {
			return ruleType, fields, true
		}
	}
	switch behavior {
	case "ipcidr":
		return "IP-CIDR", []string{line}, true
	case "domain":
		return "DOMAIN-SUFFIX", []string{line}, true
	}
	switch {
	case strings.Contains(line, "/"):
		return "IP-CIDR", []string{line}, true
	case strings.Contains(line, ".") && !strings.ContainsAny(line, " \t"):
		return "DOMAIN-SUFFIX", []string{line}, true
	default:
		return "", nil, false
	}
}

// inlineRules aggregates headless rules by matcher type so large domain/IP
// providers do not produce one JSON object per line.
type inlineRules struct {
	domains          []string
	suffixes         []string
	keywords         []string
	regexes          []string
	ipCIDRs          []string
	sourceIPCIDRs    []string
	processNames     []string
	processPaths     []string
	processPathRegex []string
	sourcePorts      []int
	sourcePortRanges []string
	ports            []int
	portRanges       []string
	networks         []string
	other            []map[string]interface{}
}

func (r *inlineRules) add(matcher map[string]interface{}) {
	for _, key := range sortedKeys(matcher) {
		value := matcher[key]
		switch key {
		case "domain":
			r.domains = append(r.domains, stringValues(value)...)
		case "domain_suffix":
			r.suffixes = append(r.suffixes, stringValues(value)...)
		case "domain_keyword":
			r.keywords = append(r.keywords, stringValues(value)...)
		case "domain_regex":
			r.regexes = append(r.regexes, stringValues(value)...)
		case "ip_cidr":
			r.ipCIDRs = append(r.ipCIDRs, stringValues(value)...)
		case "source_ip_cidr":
			r.sourceIPCIDRs = append(r.sourceIPCIDRs, stringValues(value)...)
		case "process_name":
			r.processNames = append(r.processNames, stringValues(value)...)
		case "process_path":
			r.processPaths = append(r.processPaths, stringValues(value)...)
		case "process_path_regex":
			r.processPathRegex = append(r.processPathRegex, stringValues(value)...)
		case "source_port":
			r.sourcePorts = append(r.sourcePorts, intValues(value)...)
		case "source_port_range":
			r.sourcePortRanges = append(r.sourcePortRanges, stringValues(value)...)
		case "port":
			r.ports = append(r.ports, intValues(value)...)
		case "port_range":
			r.portRanges = append(r.portRanges, stringValues(value)...)
		case "network":
			r.networks = append(r.networks, stringValues(value)...)
		default:
			r.other = append(r.other, map[string]interface{}{key: value})
		}
	}
}

func (r *inlineRules) rules() []interface{} {
	out := []interface{}{}
	appendStrings := func(key string, values []string) {
		values = sortedUniqueStrings(values)
		if len(values) > 0 {
			out = append(out, map[string]interface{}{key: values})
		}
	}
	appendInts := func(key string, values []int) {
		values = sortedUniqueInts(values)
		if len(values) > 0 {
			out = append(out, map[string]interface{}{key: values})
		}
	}
	appendStrings("domain", r.domains)
	appendStrings("domain_suffix", r.suffixes)
	appendStrings("domain_keyword", r.keywords)
	appendStrings("domain_regex", r.regexes)
	appendStrings("ip_cidr", r.ipCIDRs)
	appendStrings("source_ip_cidr", r.sourceIPCIDRs)
	appendStrings("process_name", r.processNames)
	appendStrings("process_path", r.processPaths)
	appendStrings("process_path_regex", r.processPathRegex)
	appendInts("source_port", r.sourcePorts)
	appendStrings("source_port_range", r.sourcePortRanges)
	appendInts("port", r.ports)
	appendStrings("port_range", r.portRanges)
	appendStrings("network", r.networks)
	out = append(out, mapsToInterfaces(r.other)...)
	return out
}

func stringValues(value interface{}) []string {
	return toStringSlice(value)
}

func intValues(value interface{}) []int {
	switch values := value.(type) {
	case []int:
		return values
	case []interface{}:
		out := make([]int, 0, len(values))
		for _, item := range values {
			switch n := item.(type) {
			case int:
				out = append(out, n)
			case int64:
				out = append(out, int(n))
			case float64:
				out = append(out, int(n))
			}
		}
		return out
	default:
		return nil
	}
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return uniqueStrings(out)
}

func sortedUniqueInts(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	out := append([]int(nil), values...)
	sort.Ints(out)
	unique := out[:1]
	for _, value := range out[1:] {
		if value != unique[len(unique)-1] {
			unique = append(unique, value)
		}
	}
	return unique
}

func mapsToInterfaces(values []map[string]interface{}) []interface{} {
	out := make([]interface{}, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
