package converter

import "strings"

// BuiltinPolicies returns the proxy names that always exist in target configs
// and therefore never need to be defined as proxies.
func BuiltinPolicies(extra ...string) map[string]bool {
	known := map[string]bool{
		"DIRECT":      true,
		"REJECT":      true,
		"REJECT-DROP": true,
		"PASS":        true,
		"COMPATIBLE":  true,
		"GLOBAL":      true,
		"direct":      true,
		"reject":      true,
		"reject-drop": true,
		"pass":        true,
		"compatible":  true,
		"global":      true,
	}
	for _, name := range extra {
		known[name] = true
		known[strings.ToLower(name)] = true
	}
	return known
}

// ProxyGroupNames returns the names of all proxy groups in the config.
func ProxyGroupNames(groups []map[string]interface{}) map[string]bool {
	names := make(map[string]bool, len(groups))
	for _, group := range groups {
		if name, ok := group["name"].(string); ok && name != "" {
			names[name] = true
		}
	}
	return names
}
