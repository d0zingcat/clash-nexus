package clashoutput

import (
	"context"
	"strings"
	"testing"

	"clash-nexus/converter"
)

type mockFetcher struct {
	data []byte
}

func (m *mockFetcher) Fetch(ctx context.Context, provider map[string]interface{}, basePath string) ([]byte, error) {
	return m.data, nil
}

func TestClashOutputConvertWithoutOptions(t *testing.T) {
	c := New()
	config := map[string]interface{}{
		"mode": "rule",
		"proxy-providers": map[string]interface{}{
			"p1": map[string]interface{}{"type": "http", "url": "https://p1.com"},
		},
	}
	out, warnings, err := c.Convert(config, nil)
	if err != nil {
		t.Fatalf("Convert err = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want 0", warnings)
	}
	if !strings.Contains(string(out), "proxy-providers:") {
		t.Fatalf("expected proxy-providers in output: %s", out)
	}
}

func TestClashOutputConvertWithExpand(t *testing.T) {
	mockData := `
proxies:
  - name: NodeX
    type: ss
    server: 1.1.1.1
    port: 8888
`
	c := NewWithFetcher(&mockFetcher{data: []byte(mockData)})
	config := map[string]interface{}{
		"mode": "rule",
		"proxy-providers": map[string]interface{}{
			"p1": map[string]interface{}{"type": "http", "url": "https://p1.com"},
		},
		"proxy-groups": []interface{}{
			map[string]interface{}{
				"name": "MyGroup",
				"type": "select",
				"use":  []interface{}{"p1"},
			},
		},
	}

	out, warnings, err := c.ConvertWithOptions(config, nil, converter.Options{ExpandProxyProviders: true})
	if err != nil {
		t.Fatalf("ConvertWithOptions err = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want 0", warnings)
	}
	outStr := string(out)
	if strings.Contains(outStr, "proxy-providers:") {
		t.Fatalf("proxy-providers should be removed: %s", outStr)
	}
	if !strings.Contains(outStr, "NodeX") {
		t.Fatalf("expected NodeX in output: %s", outStr)
	}
	if strings.Contains(outStr, "use:") {
		t.Fatalf("use should be removed from proxy-groups: %s", outStr)
	}
}
