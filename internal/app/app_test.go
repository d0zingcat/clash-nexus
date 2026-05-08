package app

import (
	"errors"
	"strings"
	"testing"
)

const sampleConfig = `
proxies:
  - name: direct-ss
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: pass
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - direct-ss
rules:
  - MATCH,Proxy
`

func TestConvertBytes(t *testing.T) {
	service := NewService()
	for _, target := range []string{"loon", "egern"} {
		t.Run(target, func(t *testing.T) {
			result, err := service.ConvertBytes(target, []byte(sampleConfig))
			if err != nil {
				t.Fatalf("ConvertBytes() error = %v", err)
			}
			if result.Target != target {
				t.Fatalf("Target = %q, want %q", result.Target, target)
			}
			if len(result.Content) == 0 {
				t.Fatal("Content is empty")
			}
		})
	}
}

func TestConvertBytesUnknownTarget(t *testing.T) {
	_, err := NewService().ConvertBytes("missing", []byte(sampleConfig))
	if !errors.Is(err, ErrUnknownTarget) {
		t.Fatalf("error = %v, want ErrUnknownTarget", err)
	}
}

func TestConvertBytesInvalidYAML(t *testing.T) {
	_, err := NewService().ConvertBytes("loon", []byte("proxies:\n  - ["))
	if !errors.Is(err, ErrInvalidYAML) {
		t.Fatalf("error = %v, want ErrInvalidYAML", err)
	}
}

func TestConvertBytesEmptyYAMLWarning(t *testing.T) {
	result, err := NewService().ConvertBytes("loon", nil)
	if err != nil {
		t.Fatalf("ConvertBytes() error = %v", err)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "empty YAML") {
		t.Fatalf("Warnings = %#v, want empty YAML warning", result.Warnings)
	}
}
