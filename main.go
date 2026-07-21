// clash-nexus: Convert Clash (mihomo) YAML config to multiple target formats.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"clash-nexus/internal/app"
	"clash-nexus/internal/web"
)

func main() {
	service := app.NewService()
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		runServe(service, os.Args[2:])
		return
	}
	runConvert(service, os.Args[1:])
}

func runServe(service *app.Service, args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addrFlag := fs.String("addr", "127.0.0.1:8080", "HTTP listen address")
	fs.Usage = func() {
		cmd := filepath.Base(os.Args[0])
		fmt.Fprintf(os.Stderr, "Run the local Clash Nexus web UI and conversion API.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s serve [options]\n\n", cmd)
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	fmt.Printf("Clash Nexus web UI: http://%s\n", *addrFlag)
	if err := web.ListenAndServe(*addrFlag, service); err != nil {
		fmt.Fprintf(os.Stderr, "Error: web server failed: %s\n", err)
		os.Exit(1)
	}
}

func runConvert(service *app.Service, args []string) {
	args = normalizeFlagArgs(args, map[string]bool{
		"-target": true,
		"-source": true,
		"-input":  true,
		"-o":      true,
	})
	targetHelp := service.TargetHelp()
	fs := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ExitOnError)
	targetFlag := fs.String("target", "", "Output format (required): "+targetHelp)
	sourceFlag := fs.String("source", "clash", "Input format: clash or loon")
	inputFlag := fs.String("input", "", "Path to input config file")
	outputFlag := fs.String("o", "", "Output file path (default: output/<target><ext>)")

	fs.Usage = func() {
		cmd := filepath.Base(os.Args[0])
		fmt.Fprintf(os.Stderr, "Convert Clash (mihomo) YAML config into various formats.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s -target <target> [options] [input_file]\n", cmd)
		fmt.Fprintf(os.Stderr, "  %s serve [options]\n\n", cmd)
		fmt.Fprintf(os.Stderr, "Input selection (in priority order):\n")
		fmt.Fprintf(os.Stderr, "  1. -input flag\n")
		fmt.Fprintf(os.Stderr, "  2. Positional [input_file] argument\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nAvailable targets: %s\n\n", targetHelp)
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s -target egern input/clash.yaml\n", cmd)
		fmt.Fprintf(os.Stderr, "  %s -target loon -input input/clash.yaml -o output/custom.conf\n", cmd)
		fmt.Fprintf(os.Stderr, "  %s serve -addr 127.0.0.1:8080\n\n", cmd)
		fmt.Fprintf(os.Stderr, "Output:\n")
		fmt.Fprintf(os.Stderr, "  Creates parent directories for the output file when needed.\n")
		fmt.Fprintf(os.Stderr, "  Prints a single conversion summary line after success.\n")
	}
	_ = fs.Parse(args)

	inputPath := *inputFlag
	if inputPath == "" && fs.NArg() > 0 {
		inputPath = fs.Arg(0)
	}
	if *targetFlag == "" || inputPath == "" {
		fs.Usage()
		os.Exit(1)
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot read file: %s\n", err)
		os.Exit(1)
	}

	result, err := service.ConvertBytesFrom(*sourceFlag, *targetFlag, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", warning)
	}

	outPath := *outputFlag
	if outPath == "" {
		outPath = "output/" + result.Target + result.Extension
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot create output directory: %s\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, result.Content, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot write output: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Converted (%s): %s -> %s\n", result.Target, inputPath, outPath)
}

func normalizeFlagArgs(args []string, flagsWithValue map[string]bool) []string {
	var flags []string
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		name := arg
		if idx := strings.Index(arg, "="); idx >= 0 {
			name = arg[:idx]
		}
		if strings.HasPrefix(arg, "-") && flagsWithValue[name] {
			flags = append(flags, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, arg)
	}
	return append(flags, positional...)
}
