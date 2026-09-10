// Package clashoutput serializes the shared Clash/Mihomo model.
package clashoutput

import (
	"gopkg.in/yaml.v3"

	"clash-nexus/converter"
	"clash-nexus/converter/clash"
)

type Converter struct {
	Fetcher clash.ProviderFetcher
}

func New() *Converter { return &Converter{} }
func NewWithFetcher(fetcher clash.ProviderFetcher) *Converter {
	return &Converter{Fetcher: fetcher}
}

func (c *Converter) Name() string             { return "clash" }
func (c *Converter) DefaultExtension() string { return ".yaml" }

func (c *Converter) Convert(config map[string]interface{}, root *yaml.Node) ([]byte, []string, error) {
	return c.ConvertWithOptions(config, root, converter.Options{})
}

func (c *Converter) ConvertWithOptions(config map[string]interface{}, root *yaml.Node, options converter.Options) ([]byte, []string, error) {
	var warnings []string
	if options.ExpandProxyProviders {
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
	data, err := yaml.Marshal(config)
	return data, warnings, err
}
