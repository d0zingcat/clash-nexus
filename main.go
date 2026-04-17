// clash-nexus: Convert Clash (mihomo) YAML config to multiple target formats.
package main

import (
"flag"
"fmt"
"os"
"path/filepath"
"sort"
"strings"

"gopkg.in/yaml.v3"

"clash-nexus/converter"
"clash-nexus/converter/egern"
"clash-nexus/converter/loon"
)

// registry holds all available converters keyed by name.
var registry = map[string]converter.Converter{
"loon":  loon.New(),
"egern": egern.New(),
}

func main() {
// Build sorted list of available target names for help text.
targets := make([]string, 0, len(registry))
for k := range registry {
targets = append(targets, k)
}
sort.Strings(targets)
targetHelp := strings.Join(targets, ", ")

targetFlag := flag.String("target", "", "Output format (required): "+targetHelp)
inputFlag := flag.String("input", "", "Path to Clash YAML config file")
outputFlag := flag.String("o", "", "Output file path (default: output/<target><ext>)")

flag.Usage = func() {
cmd := filepath.Base(os.Args[0])
fmt.Fprintf(os.Stderr, "Convert Clash (mihomo) YAML config into various formats.\n\n")
fmt.Fprintf(os.Stderr, "Usage:\n")
fmt.Fprintf(os.Stderr, "  %s -target <target> [options] [input_file]\n\n", cmd)
fmt.Fprintf(os.Stderr, "Input selection (in priority order):\n")
fmt.Fprintf(os.Stderr, "  1. -input flag\n")
fmt.Fprintf(os.Stderr, "  2. Positional [input_file] argument\n\n")
fmt.Fprintf(os.Stderr, "Options:\n")
flag.PrintDefaults()
fmt.Fprintf(os.Stderr, "\nAvailable targets: %s\n\n", targetHelp)
fmt.Fprintf(os.Stderr, "Examples:\n")
fmt.Fprintf(os.Stderr, "  %s -target egern input/clash.yaml\n", cmd)
fmt.Fprintf(os.Stderr, "  %s -target loon -input input/clash.yaml -o output/custom.conf\n\n", cmd)
fmt.Fprintf(os.Stderr, "Output:\n")
fmt.Fprintf(os.Stderr, "  Creates parent directories for the output file when needed.\n")
fmt.Fprintf(os.Stderr, "  Prints a single conversion summary line after success.\n")
}
flag.Parse()

// Resolve input path.
inputPath := *inputFlag
if inputPath == "" && flag.NArg() > 0 {
inputPath = flag.Arg(0)
}

// Both -target and input are required; show usage if either is missing.
if *targetFlag == "" || inputPath == "" {
flag.Usage()
os.Exit(1)
}

// Resolve converter.
conv, ok := registry[*targetFlag]
if !ok {
fmt.Fprintf(os.Stderr, "Error: unknown target '%s'. Available: %s\n", *targetFlag, targetHelp)
os.Exit(1)
}

// Resolve output path.
outPath := *outputFlag
if outPath == "" {
outPath = "output/" + conv.Name() + conv.DefaultExtension()
}

// Read and parse input.
data, err := os.ReadFile(inputPath)
if err != nil {
fmt.Fprintf(os.Stderr, "Error: cannot read file: %s\n", err)
os.Exit(1)
}

var config map[string]interface{}
if err := yaml.Unmarshal(data, &config); err != nil {
fmt.Fprintf(os.Stderr, "Error: invalid YAML: %s\n", err)
os.Exit(1)
}
if config == nil {
fmt.Fprintf(os.Stderr, "Warning: empty or invalid YAML, generating skeleton config\n")
config = map[string]interface{}{}
}

var rootNode yaml.Node
_ = yaml.Unmarshal(data, &rootNode)

// Convert.
result, err := conv.Convert(config, &rootNode)
if err != nil {
fmt.Fprintf(os.Stderr, "Error: conversion failed: %s\n", err)
os.Exit(1)
}

// Write output.
if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
fmt.Fprintf(os.Stderr, "Error: cannot create output directory: %s\n", err)
os.Exit(1)
}
if err := os.WriteFile(outPath, result, 0644); err != nil {
fmt.Fprintf(os.Stderr, "Error: cannot write output: %s\n", err)
os.Exit(1)
}

fmt.Printf("Converted (%s): %s -> %s\n", conv.Name(), inputPath, outPath)
}
