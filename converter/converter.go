// Package converter defines the common interface for Clash-config converters.
package converter

import "gopkg.in/yaml.v3"

// Converter converts a Clash (mihomo) YAML configuration to another format.
// Each implementation handles a specific target (e.g. Loon, Egern).
type Converter interface {
	// Name returns the short identifier used in CLI flags (e.g. "loon", "egern").
	Name() string
	// DefaultExtension returns the file extension for the generated output
	// (e.g. ".conf", ".yaml").
	DefaultExtension() string
	// Convert transforms the parsed Clash config map and its underlying YAML
	// node tree into the target format. The YAML node tree is provided so
	// converters can preserve key insertion order when needed.
	Convert(config map[string]interface{}, root *yaml.Node) ([]byte, error)
}
