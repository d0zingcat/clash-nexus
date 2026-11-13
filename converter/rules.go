package converter

import (
	"fmt"
	"strings"
)

// RejectRemovedProxyRules preserves rule ordering and matchers when a target
// cannot emit a source proxy. Rejecting the matching traffic avoids both dangling
// policies and accidentally sending it through the default route.
// Input rules are copied; provider-only policies and group names are untouched.
func RejectRemovedProxyRules(rules []interface{}, proxies, groups []map[string]interface{}, available map[string]bool, target string, warnings *[]string) []interface{} {
	known := BuiltinPolicies()
	for name := range ProxyGroupNames(groups) {
		known[name] = true
	}
	removed := map[string]bool{}
	for _, proxy := range proxies {
		name, _ := proxy["name"].(string)
		if name != "" && !known[name] && !available[name] {
			removed[name] = true
		}
	}
	out := append([]interface{}(nil), rules...)
	for i, raw := range out {
		rule, ok := raw.(string)
		if !ok {
			continue
		}
		// Commas inside logical matchers (including nested expressions) are
		// not policy separators. Preserve the original matcher and modifiers.
		starts := []int{0}
		depth := 0
		for j, ch := range rule {
			switch ch {
			case '(':
				depth++
			case ')':
				depth--
			case ',':
				if depth == 0 {
					starts = append(starts, j+1)
				}
			}
		}
		policyIndex := 2
		kindEnd := strings.IndexByte(rule, ',')
		if kindEnd < 0 {
			continue
		}
		kind := strings.ToUpper(strings.TrimSpace(rule[:kindEnd]))
		if kind == "MATCH" || kind == "FINAL" {
			policyIndex = 1
		}
		if len(starts) <= policyIndex || depth != 0 {
			continue
		}
		start, end := starts[policyIndex], len(rule)
		if len(starts) > policyIndex+1 {
			end = starts[policyIndex+1] - 1
		}
		policy := strings.TrimSpace(rule[start:end])
		if removed[policy] {
			out[i] = rule[:start] + "REJECT" + rule[end:]
			*warnings = append(*warnings, fmt.Sprintf("rule policy %q was removed by %s conversion; using REJECT", policy, target))
		}
	}
	return out
}
