// Package clashoutput serializes the shared Clash/Mihomo model.
package clashoutput

import "gopkg.in/yaml.v3"

type Converter struct{}

func New() *Converter                         { return &Converter{} }
func (c *Converter) Name() string             { return "clash" }
func (c *Converter) DefaultExtension() string { return ".yaml" }
func (c *Converter) Convert(config map[string]interface{}, _ *yaml.Node) ([]byte, []string, error) {
	data, err := yaml.Marshal(config)
	return data, nil, err
}
