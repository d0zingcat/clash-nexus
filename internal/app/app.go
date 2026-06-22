// Package app exposes the shared conversion service used by the CLI and web API.
package app

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"clash-nexus/converter"
	"clash-nexus/converter/clashoutput"
	"clash-nexus/converter/egern"
	"clash-nexus/converter/loon"
	"clash-nexus/converter/looninput"
	"clash-nexus/converter/qx"
)

var (
	ErrUnknownTarget         = errors.New("unknown target")
	ErrInvalidYAML           = errors.New("invalid yaml")
	ErrConvertFailed         = errors.New("conversion failed")
	ErrUnknownSource         = errors.New("unknown source")
	ErrInvalidLoon           = errors.New("invalid loon")
	ErrUnsupportedConversion = errors.New("unsupported conversion")
)

// Target describes a registered output format.
type Target struct {
	Name      string `json:"name"`
	Extension string `json:"extension"`
}

// Result is the normalized output of a conversion.
type Result struct {
	Target    string   `json:"target"`
	Filename  string   `json:"filename"`
	Extension string   `json:"extension"`
	Content   []byte   `json:"-"`
	Warnings  []string `json:"warnings,omitempty"`
}

// Service owns converter registration and shared conversion behavior.
type Service struct {
	registry map[string]converter.Converter
}

// NewService returns a service with all built-in converters registered.
func NewService() *Service {
	return &Service{registry: map[string]converter.Converter{
		"loon":  loon.New(),
		"clash": clashoutput.New(),
		"egern": egern.New(),
		"qx":    qx.New(),
	}}
}

// ConvertBytesFrom converts a supported source format to a target format.
func (s *Service) ConvertBytesFrom(source, target string, data []byte) (Result, error) {
	return s.ConvertBytesFromWithOptions(source, target, data, converter.Options{})
}

// ConvertBytesFromWithOptions converts a supported source format with target options.
func (s *Service) ConvertBytesFromWithOptions(source, target string, data []byte, options converter.Options) (Result, error) {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" || source == "clash" {
		return s.ConvertBytes(target, data)
	}
	if source != "loon" {
		return Result{}, fmt.Errorf("%w: %s", ErrUnknownSource, source)
	}
	if strings.EqualFold(target, "loon") {
		return Result{}, fmt.Errorf("%w: loon -> loon", ErrUnsupportedConversion)
	}
	config, warnings, err := looninput.Parse(data)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidLoon, err)
	}
	conv, ok := s.Converter(target)
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrUnknownTarget, target)
	}
	var content []byte
	var convertWarnings []string
	if optConv, ok := conv.(converter.OptionConverter); ok {
		content, convertWarnings, err = optConv.ConvertWithOptions(config, nil, options)
	} else {
		content, convertWarnings, err = conv.Convert(config, nil)
	}
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrConvertFailed, err)
	}
	return Result{Target: conv.Name(), Filename: "converted." + conv.Name() + conv.DefaultExtension(), Extension: conv.DefaultExtension(), Content: content, Warnings: append(warnings, convertWarnings...)}, nil
}

// Targets returns all registered targets in stable order.
func (s *Service) Targets() []Target {
	targets := make([]Target, 0, len(s.registry))
	for _, conv := range s.registry {
		targets = append(targets, Target{
			Name:      conv.Name(),
			Extension: conv.DefaultExtension(),
		})
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Name < targets[j].Name
	})
	return targets
}

// TargetHelp returns a comma-separated list suitable for CLI help text.
func (s *Service) TargetHelp() string {
	names := make([]string, 0, len(s.registry))
	for _, target := range s.Targets() {
		names = append(names, target.Name)
	}
	return strings.Join(names, ", ")
}

// Converter returns a registered converter by name.
func (s *Service) Converter(target string) (converter.Converter, bool) {
	conv, ok := s.registry[target]
	return conv, ok
}

// ConvertBytes converts Clash YAML bytes to the requested target format.
func (s *Service) ConvertBytes(target string, data []byte) (Result, error) {
	return s.ConvertBytesWithOptions(target, data, converter.Options{})
}

// ConvertBytesWithOptions converts Clash YAML bytes using target-specific options.
func (s *Service) ConvertBytesWithOptions(target string, data []byte, options converter.Options) (Result, error) {
	conv, ok := s.Converter(target)
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrUnknownTarget, target)
	}

	var warnings []string
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidYAML, err)
	}
	if config == nil {
		warnings = append(warnings, "empty YAML, generated skeleton config")
		config = map[string]interface{}{}
	}

	var rootNode yaml.Node
	_ = yaml.Unmarshal(data, &rootNode)

	var content []byte
	var convertWarnings []string
	var err error
	if optConv, ok := conv.(converter.OptionConverter); ok {
		content, convertWarnings, err = optConv.ConvertWithOptions(config, &rootNode, options)
	} else {
		content, convertWarnings, err = conv.Convert(config, &rootNode)
	}
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrConvertFailed, err)
	}
	warnings = append(warnings, convertWarnings...)

	return Result{
		Target:    conv.Name(),
		Filename:  "converted." + conv.Name() + conv.DefaultExtension(),
		Extension: conv.DefaultExtension(),
		Content:   content,
		Warnings:  warnings,
	}, nil
}
