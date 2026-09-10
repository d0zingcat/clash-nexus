// Package clash provides helper utilities and transformations for Clash YAML configs.
package clash

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"gopkg.in/yaml.v3"
)

const maxProviderBytes = 10 * 1024 * 1024 // 10 MiB

// ProviderFetcher abstracts fetching provider data (HTTP or local file).
type ProviderFetcher interface {
	Fetch(ctx context.Context, provider map[string]interface{}, basePath string) ([]byte, error)
}

// DefaultFetcher fetches remote providers via HTTP and local files via filesystem.
type DefaultFetcher struct {
	Client   *http.Client
	BasePath string
}

// NewDefaultFetcher returns a DefaultFetcher with standard timeouts and redirects.
func NewDefaultFetcher(client *http.Client, basePath string) *DefaultFetcher {
	if client == nil {
		client = &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				return nil
			},
		}
	}
	return &DefaultFetcher{
		Client:   client,
		BasePath: basePath,
	}
}

// Fetch fetches the raw YAML bytes for a proxy provider.
func (f *DefaultFetcher) Fetch(ctx context.Context, provider map[string]interface{}, basePath string) ([]byte, error) {
	if basePath == "" {
		basePath = f.BasePath
	}
	pType := strings.ToLower(MapGetStr(provider, "type", ""))
	rawURL := strings.TrimSpace(MapGetStr(provider, "url", ""))
	filePath := strings.TrimSpace(MapGetStr(provider, "path", ""))

	// If type is file or url is empty, read directly from local path.
	if pType == "file" || (rawURL == "" && filePath != "") {
		return f.readLocalFile(filePath, basePath)
	}

	if rawURL == "" {
		return nil, errors.New("provider has neither url nor path")
	}

	// Fetch via HTTP
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid request url %q: %w", rawURL, err)
	}

	// Default User-Agent to clash.meta so airport subscriptions return Clash format.
	req.Header.Set("User-Agent", "clash.meta")

	// Apply custom headers if present (supports both 'header' and 'headers')
	applyCustomHeaders(req, provider["header"])
	applyCustomHeaders(req, provider["headers"])

	resp, err := f.Client.Do(req)
	if err != nil {
		// If HTTP failed, attempt to fall back to cached local file at filePath if it exists
		if filePath != "" {
			if localData, readErr := f.readLocalFile(filePath, basePath); readErr == nil && len(localData) > 0 {
				return localData, nil
			}
		}
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if filePath != "" {
			if localData, readErr := f.readLocalFile(filePath, basePath); readErr == nil && len(localData) > 0 {
				return localData, nil
			}
		}
		return nil, fmt.Errorf("http error %d: %s", resp.StatusCode, resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if len(data) > maxProviderBytes {
		return nil, errors.New("provider response exceeds 10 MiB limit")
	}
	return data, nil
}

func (f *DefaultFetcher) readLocalFile(path, basePath string) ([]byte, error) {
	targetPath := path
	if !filepath.IsAbs(targetPath) && basePath != "" {
		targetPath = filepath.Join(basePath, targetPath)
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read local file %q: %w", targetPath, err)
	}
	return data, nil
}

func applyCustomHeaders(req *http.Request, raw interface{}) {
	if raw == nil {
		return
	}
	headersMap := AnyMap(raw)
	if headersMap == nil {
		return
	}
	for k, v := range headersMap {
		switch val := v.(type) {
		case []interface{}:
			for _, item := range val {
				req.Header.Add(k, fmt.Sprintf("%v", item))
			}
		case []string:
			for _, item := range val {
				req.Header.Add(k, item)
			}
		default:
			req.Header.Set(k, fmt.Sprintf("%v", val))
		}
	}
}

// ExpandOptions configures the provider expansion behavior.
type ExpandOptions struct {
	Fetcher  ProviderFetcher
	BasePath string
	RootNode *yaml.Node
}

type providerNode struct {
	ProviderName string
	OriginalName string
	FinalName    string
	Type         string
	ProxyData    map[string]interface{}
}

// ExpandProxyProviders expands all proxy-providers in the config into concrete
// proxies, rewrites proxy-groups referencing them via 'use', and deletes 'proxy-providers'.
func ExpandProxyProviders(config map[string]interface{}, opts ExpandOptions) ([]string, error) {
	providersRaw, ok := config["proxy-providers"]
	if !ok || providersRaw == nil {
		return nil, nil
	}
	providersMap := AnyMap(providersRaw)
	if len(providersMap) == 0 {
		delete(config, "proxy-providers")
		return nil, nil
	}

	fetcher := opts.Fetcher
	if fetcher == nil {
		fetcher = NewDefaultFetcher(nil, opts.BasePath)
	}

	var warnings []string

	// Determine stable order of providers
	providerOrder := OrderedKeysFromNode(opts.RootNode, "proxy-providers")
	if len(providerOrder) == 0 {
		providerOrder = make([]string, 0, len(providersMap))
		for name := range providersMap {
			providerOrder = append(providerOrder, name)
		}
		sort.Strings(providerOrder)
	}

	// Register existing top-level proxy names to detect collisions
	existingProxies := ToMapSlice(config["proxies"])
	assignedNames := make(map[string]bool, len(existingProxies))
	for _, p := range existingProxies {
		name := MapGetStr(p, "name", "")
		if name != "" {
			assignedNames[name] = true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Map of providerName -> list of resolved providerNodes
	providerNodesMap := make(map[string][]providerNode, len(providerOrder))

	for _, providerName := range providerOrder {
		rawDef, exists := providersMap[providerName]
		if !exists {
			continue
		}
		providerDef := AnyMap(rawDef)
		if providerDef == nil {
			warnings = append(warnings, fmt.Sprintf("proxy provider %q is not a mapping, skipping", providerName))
			continue
		}

		data, err := fetcher.Fetch(ctx, providerDef, opts.BasePath)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("failed to fetch proxy provider %q: %v", providerName, err))
			continue
		}

		proxies, err := parseProviderProxies(data)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("failed to parse proxies for provider %q: %v", providerName, err))
			continue
		}

		// Compile provider-level filters
		pFilter, err := compileFilter(MapGetStr(providerDef, "filter", ""))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("provider %q invalid filter regex: %v", providerName, err))
		}
		pExcludeFilter, err := compileFilter(MapGetStr(providerDef, "exclude-filter", ""))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("provider %q invalid exclude-filter regex: %v", providerName, err))
		}
		pExcludeType, err := compileFilter(MapGetStr(providerDef, "exclude-type", ""))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("provider %q invalid exclude-type regex: %v", providerName, err))
		}

		var survivingNodes []providerNode
		for _, proxy := range proxies {
			origName := MapGetStr(proxy, "name", "")
			proxyType := MapGetStr(proxy, "type", "")
			if origName == "" || proxyType == "" {
				continue
			}

			// Apply provider-level filters against original name and type
			if pFilter != nil && !matchFilter(pFilter, origName) {
				continue
			}
			if matchFilter(pExcludeFilter, origName) {
				continue
			}
			if matchFilter(pExcludeType, proxyType) {
				continue
			}

			// Disambiguate name if colliding with top-level or other providers
			finalName := origName
			if assignedNames[finalName] {
				finalName = fmt.Sprintf("[%s] %s", providerName, origName)
				if assignedNames[finalName] {
					idx := 2
					for assignedNames[fmt.Sprintf("[%s] %s (%d)", providerName, origName, idx)] {
						idx++
					}
					finalName = fmt.Sprintf("[%s] %s (%d)", providerName, origName, idx)
				}
			}
			assignedNames[finalName] = true

			// Create a copy of the proxy map with the assigned final name
			proxyCopy := make(map[string]interface{}, len(proxy))
			for k, v := range proxy {
				proxyCopy[k] = v
			}
			proxyCopy["name"] = finalName

			survivingNodes = append(survivingNodes, providerNode{
				ProviderName: providerName,
				OriginalName: origName,
				FinalName:    finalName,
				Type:         proxyType,
				ProxyData:    proxyCopy,
			})
		}

		providerNodesMap[providerName] = survivingNodes
	}

	// Process proxy-groups
	groups := ToMapSlice(config["proxy-groups"])
	for _, group := range groups {
		uses := ToStringSlice(group["use"])
		if len(uses) == 0 {
			continue
		}

		groupName := MapGetStr(group, "name", "")
		gFilter, err := compileFilter(MapGetStr(group, "filter", ""))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("proxy group %q invalid filter regex: %v", groupName, err))
		}
		gExcludeFilter, err := compileFilter(MapGetStr(group, "exclude-filter", ""))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("proxy group %q invalid exclude-filter regex: %v", groupName, err))
		}
		gExcludeType, err := compileFilter(MapGetStr(group, "exclude-type", ""))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("proxy group %q invalid exclude-type regex: %v", groupName, err))
		}

		// Collect existing proxies in the group
		existingMembers := ToStringSlice(group["proxies"])
		memberSet := make(map[string]bool, len(existingMembers))
		for _, m := range existingMembers {
			memberSet[m] = true
		}

		var addedMembers []string
		for _, useName := range uses {
			nodes, exists := providerNodesMap[useName]
			if !exists {
				warnings = append(warnings, fmt.Sprintf("proxy group %q references unknown or empty provider %q", groupName, useName))
				continue
			}

			for _, node := range nodes {
				// Evaluate group filters against node original name and type
				if gFilter != nil && !matchFilter(gFilter, node.OriginalName) {
					continue
				}
				if matchFilter(gExcludeFilter, node.OriginalName) {
					continue
				}
				if matchFilter(gExcludeType, node.Type) {
					continue
				}

				if !memberSet[node.FinalName] {
					memberSet[node.FinalName] = true
					addedMembers = append(addedMembers, node.FinalName)
				}
			}
		}

		combined := append(existingMembers, addedMembers...)
		if len(combined) == 0 {
			warnings = append(warnings, fmt.Sprintf("proxy group %q has no proxies after expanding providers, added DIRECT fallback", groupName))
			combined = []string{"DIRECT"}
		}

		group["proxies"] = combined
		delete(group, "use")
		delete(group, "filter")
		delete(group, "exclude-filter")
		delete(group, "exclude-type")
	}

	// Append all provider nodes to top-level proxies
	allProxies := make([]interface{}, 0, len(existingProxies)+len(assignedNames))
	for _, p := range existingProxies {
		allProxies = append(allProxies, p)
	}
	for _, providerName := range providerOrder {
		for _, node := range providerNodesMap[providerName] {
			allProxies = append(allProxies, node.ProxyData)
		}
	}
	config["proxies"] = allProxies

	// Remove proxy-providers from top-level
	delete(config, "proxy-providers")

	return warnings, nil
}

func parseProviderProxies(data []byte) ([]map[string]interface{}, error) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err == nil && doc != nil {
		if proxiesRaw, ok := doc["proxies"]; ok {
			return ToMapSlice(proxiesRaw), nil
		}
	}

	var list []interface{}
	if err := yaml.Unmarshal(data, &list); err == nil && len(list) > 0 {
		return ToMapSlice(list), nil
	}

	return nil, errors.New("no proxies found in YAML content")
}

func compileFilter(pattern string) (*regexp2.Regexp, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, nil
	}
	return regexp2.Compile(pattern, regexp2.None)
}

func matchFilter(re *regexp2.Regexp, s string) bool {
	if re == nil {
		return false
	}
	matched, _ := re.MatchString(s)
	return matched
}
