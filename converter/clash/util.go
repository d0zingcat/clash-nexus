// Package clash provides helper utilities for reading Clash YAML config maps.
package clash

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// AnyMap normalises any YAML mapping to map[string]interface{}.
func AnyMap(v interface{}) map[string]interface{} {
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

// MapGet retrieves a typed value from the map.
func MapGet[T any](m map[string]interface{}, key string) (T, bool) {
	v, ok := m[key]
	if !ok {
		var z T
		return z, false
	}
	t, ok := v.(T)
	return t, ok
}

// MapGetMap retrieves a nested mapping value tolerating both map types.
func MapGetMap(m map[string]interface{}, key string) map[string]interface{} {
	return AnyMap(m[key])
}

// MapGetStr retrieves a string value, falling back to def when missing.
func MapGetStr(m map[string]interface{}, key string, def string) string {
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

// MapGetBool retrieves a bool value, falling back to def when missing.
func MapGetBool(m map[string]interface{}, key string, def bool) bool {
	v, ok := m[key]
	if !ok {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

// MapGetInt retrieves an int value, falling back to def when missing.
func MapGetInt(m map[string]interface{}, key string, def int) int {
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

// ToStringSlice converts a generic interface{} to []string.
func ToStringSlice(v interface{}) []string {
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

// ToMapSlice converts a generic interface{} to []map[string]interface{}.
func ToMapSlice(v interface{}) []map[string]interface{} {
	if v == nil {
		return nil
	}
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		if m := AnyMap(item); m != nil {
			out = append(out, m)
		}
	}
	return out
}

// ToOrderedMap returns the keys and the map for a generic interface{} value.
// Key order is not guaranteed (yaml.v3 returns sorted keys).
func ToOrderedMap(v interface{}) ([]string, map[string]interface{}) {
	m := AnyMap(v)
	if m == nil {
		return nil, nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys, m
}

// OrderedKeysFromNode extracts the keys of a top-level mapping field in the
// given yaml.Node document, preserving original YAML document order.
func OrderedKeysFromNode(root *yaml.Node, field string) []string {
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

// BoolStr converts a bool to "true"/"false".
func BoolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
