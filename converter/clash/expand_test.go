package clash

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type mockFetcher struct {
	responses map[string][]byte
	errs      map[string]error
}

func (m *mockFetcher) Fetch(ctx context.Context, provider map[string]interface{}, basePath string) ([]byte, error) {
	name := MapGetStr(provider, "url", "")
	if name == "" {
		name = MapGetStr(provider, "path", "")
	}
	if err, ok := m.errs[name]; ok {
		return nil, err
	}
	if data, ok := m.responses[name]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("mock: not found %s", name)
}

func TestExpandProxyProvidersBasic(t *testing.T) {
	providerYAML := `
proxies:
  - name: "🇭🇰 HK 01"
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-128-gcm
    password: pass
  - name: "🇺🇸 US 01"
    type: vmess
    server: us.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-123456789abc
`
	config := map[string]interface{}{
		"proxy-providers": map[string]interface{}{
			"airport-a": map[string]interface{}{
				"type": "http",
				"url":  "https://airport.com/sub.yaml",
			},
		},
		"proxy-groups": []interface{}{
			map[string]interface{}{
				"name": "HK Group",
				"type": "select",
				"use":  []interface{}{"airport-a"},
				"filter": "HK",
			},
			map[string]interface{}{
				"name": "All Nodes",
				"type": "select",
				"use":  []interface{}{"airport-a"},
				"proxies": []interface{}{"DIRECT"},
			},
		},
	}

	fetcher := &mockFetcher{
		responses: map[string][]byte{
			"https://airport.com/sub.yaml": []byte(providerYAML),
		},
	}

	warnings, err := ExpandProxyProviders(config, ExpandOptions{Fetcher: fetcher})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	// 1. Check proxy-providers removed
	if _, exists := config["proxy-providers"]; exists {
		t.Fatal("proxy-providers should be removed")
	}

	// 2. Check top-level proxies populated
	proxies := ToMapSlice(config["proxies"])
	if len(proxies) != 2 {
		t.Fatalf("proxies count = %d, want 2", len(proxies))
	}
	if proxies[0]["name"] != "🇭🇰 HK 01" || proxies[1]["name"] != "🇺🇸 US 01" {
		t.Fatalf("unexpected proxies: %#v", proxies)
	}

	// 3. Check HK Group has only HK node and no 'use' or 'filter'
	groups := ToMapSlice(config["proxy-groups"])
	hkGroup := groups[0]
	if _, hasUse := hkGroup["use"]; hasUse {
		t.Fatal("HK Group should not have 'use'")
	}
	if _, hasFilter := hkGroup["filter"]; hasFilter {
		t.Fatal("HK Group should not have 'filter'")
	}
	hkMembers := ToStringSlice(hkGroup["proxies"])
	if len(hkMembers) != 1 || hkMembers[0] != "🇭🇰 HK 01" {
		t.Fatalf("HK Group members = %#v, want ['🇭🇰 HK 01']", hkMembers)
	}

	// 4. Check All Nodes preserves DIRECT and appends both provider nodes
	allGroup := groups[1]
	allMembers := ToStringSlice(allGroup["proxies"])
	if len(allMembers) != 3 || allMembers[0] != "DIRECT" || allMembers[1] != "🇭🇰 HK 01" || allMembers[2] != "🇺🇸 US 01" {
		t.Fatalf("All Nodes members = %#v, want ['DIRECT', '🇭🇰 HK 01', '🇺🇸 US 01']", allMembers)
	}
}

func TestExpandProxyProvidersCollisionHandling(t *testing.T) {
	providerAYAML := `
proxies:
  - name: "Node 1"
    type: ss
    server: 1.1.1.1
    port: 8388
`
	providerBYAML := `
proxies:
  - name: "Node 1"
    type: ss
    server: 2.2.2.2
    port: 8388
`
	config := map[string]interface{}{
		"proxies": []interface{}{
			map[string]interface{}{
				"name": "Node 1",
				"type": "ss",
				"server": "0.0.0.0",
				"port": 8388,
			},
		},
		"proxy-providers": map[string]interface{}{
			"sub-a": map[string]interface{}{
				"type": "http",
				"url":  "https://a.com",
			},
			"sub-b": map[string]interface{}{
				"type": "http",
				"url":  "https://b.com",
			},
		},
		"proxy-groups": []interface{}{
			map[string]interface{}{
				"name": "Group",
				"type": "select",
				"use":  []interface{}{"sub-a", "sub-b"},
				"filter": "Node 1",
			},
		},
	}

	fetcher := &mockFetcher{
		responses: map[string][]byte{
			"https://a.com": []byte(providerAYAML),
			"https://b.com": []byte(providerBYAML),
		},
	}

	warnings, err := ExpandProxyProviders(config, ExpandOptions{Fetcher: fetcher})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	proxies := ToMapSlice(config["proxies"])
	if len(proxies) != 3 {
		t.Fatalf("proxies count = %d, want 3", len(proxies))
	}
	if proxies[0]["name"] != "Node 1" {
		t.Fatalf("proxy 0 name = %q, want 'Node 1'", proxies[0]["name"])
	}
	if proxies[1]["name"] != "[sub-a] Node 1" {
		t.Fatalf("proxy 1 name = %q, want '[sub-a] Node 1'", proxies[1]["name"])
	}
	if proxies[2]["name"] != "[sub-b] Node 1" {
		t.Fatalf("proxy 2 name = %q, want '[sub-b] Node 1'", proxies[2]["name"])
	}

	groups := ToMapSlice(config["proxy-groups"])
	groupMembers := ToStringSlice(groups[0]["proxies"])
	if len(groupMembers) != 2 || groupMembers[0] != "[sub-a] Node 1" || groupMembers[1] != "[sub-b] Node 1" {
		t.Fatalf("group members = %#v, want ['[sub-a] Node 1', '[sub-b] Node 1']", groupMembers)
	}
}

func TestExpandProxyProvidersEmptyFallback(t *testing.T) {
	providerYAML := `
proxies:
  - name: "US 01"
    type: ss
    server: 1.1.1.1
    port: 8388
`
	config := map[string]interface{}{
		"proxy-providers": map[string]interface{}{
			"sub-a": map[string]interface{}{
				"type": "http",
				"url":  "https://a.com",
			},
		},
		"proxy-groups": []interface{}{
			map[string]interface{}{
				"name": "HK Group",
				"type": "select",
				"use":  []interface{}{"sub-a"},
				"filter": "HK", // Does not match US 01
			},
		},
	}

	fetcher := &mockFetcher{
		responses: map[string][]byte{
			"https://a.com": []byte(providerYAML),
		},
	}

	warnings, err := ExpandProxyProviders(config, ExpandOptions{Fetcher: fetcher})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected warning about empty group")
	}

	groups := ToMapSlice(config["proxy-groups"])
	members := ToStringSlice(groups[0]["proxies"])
	if len(members) != 1 || members[0] != "DIRECT" {
		t.Fatalf("expected ['DIRECT'], got %#v", members)
	}
}

func TestExpandProxyProvidersProviderLevelFilters(t *testing.T) {
	providerYAML := `
proxies:
  - name: "HK 01"
    type: ss
    server: 1.1.1.1
    port: 8388
  - name: "US 01"
    type: vmess
    server: 2.2.2.2
    port: 443
  - name: "HK Expired"
    type: ss
    server: 3.3.3.3
    port: 8388
`
	config := map[string]interface{}{
		"proxy-providers": map[string]interface{}{
			"sub-a": map[string]interface{}{
				"type": "http",
				"url":  "https://a.com",
				"filter": "HK",
				"exclude-filter": "Expired",
			},
		},
		"proxy-groups": []interface{}{
			map[string]interface{}{
				"name": "Group",
				"type": "select",
				"use":  []interface{}{"sub-a"},
			},
		},
	}

	fetcher := &mockFetcher{
		responses: map[string][]byte{
			"https://a.com": []byte(providerYAML),
		},
	}

	warnings, err := ExpandProxyProviders(config, ExpandOptions{Fetcher: fetcher})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	proxies := ToMapSlice(config["proxies"])
	if len(proxies) != 1 || proxies[0]["name"] != "HK 01" {
		t.Fatalf("proxies = %#v, want only ['HK 01']", proxies)
	}
}

func TestDefaultFetcherLocalFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "local_sub.yaml")
	content := []byte("proxies:\n  - name: LocalNode\n    type: ss\n    server: 1.1.1.1\n    port: 8388\n")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatal(err)
	}

	fetcher := NewDefaultFetcher(nil, tmpDir)
	data, err := fetcher.Fetch(context.Background(), map[string]interface{}{
		"type": "file",
		"path": "local_sub.yaml",
	}, tmpDir)
	if err != nil {
		t.Fatalf("Fetch error = %v", err)
	}
	if string(data) != string(content) {
		t.Fatalf("got %s, want %s", string(data), string(content))
	}
}
