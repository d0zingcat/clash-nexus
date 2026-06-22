// Package looninput parses a Loon configuration into the Clash-shaped model
// used by the existing output converters.
package looninput

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// Parse converts supported Loon sections to a Clash configuration map.
func Parse(data []byte) (map[string]interface{}, []string, error) {
	config := map[string]interface{}{}
	var proxies, groups, rules []interface{}
	providers := map[string]interface{}{}
	var warnings []string
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		switch section {
		case "proxy":
			proxy, err := parseProxy(line)
			if err != nil {
				return nil, nil, fmt.Errorf("line %d [Proxy]: %w", lineNo, err)
			}
			proxies = append(proxies, proxy)
		case "proxy group":
			group, err := parseGroup(line)
			if err != nil {
				return nil, nil, fmt.Errorf("line %d [Proxy Group]: %w", lineNo, err)
			}
			groups = append(groups, group)
		case "rule":
			rule := normalizeRule(line)
			if rule != "" {
				rules = append(rules, rule)
			}
		case "remote rule":
			name, provider, rule, err := parseRemoteRule(line)
			if err != nil {
				return nil, nil, fmt.Errorf("line %d [Remote Rule]: %w", lineNo, err)
			}
			providers[name] = provider
			rules = append(rules, rule)
		case "", "general":
			if section == "general" {
				warnings = append(warnings, fmt.Sprintf("[General] entry not converted: %s", line))
			}
		default:
			warnings = append(warnings, fmt.Sprintf("[%s] is not supported and was skipped", section))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	if len(proxies) > 0 {
		config["proxies"] = proxies
	}
	if len(groups) > 0 {
		config["proxy-groups"] = groups
	}
	if len(providers) > 0 {
		config["rule-providers"] = providers
	}
	if len(rules) > 0 {
		config["rules"] = rules
	}
	return config, warnings, nil
}

func parseProxy(line string) (map[string]interface{}, error) {
	name, value, ok := strings.Cut(line, "=")
	if !ok {
		return nil, fmt.Errorf("expected name = proxy")
	}
	parts := split(value)
	if len(parts) < 3 {
		return nil, fmt.Errorf("proxy needs type, server, and port")
	}
	typeName := strings.ToLower(parts[0])
	types := map[string]string{"shadowsocks": "ss", "shadowsocksr": "ssr", "vmess": "vmess", "vless": "vless", "trojan": "trojan", "hysteria": "hysteria", "hysteria2": "hysteria2", "wireguard": "wireguard"}
	typ := types[typeName]
	if typ == "" {
		return nil, fmt.Errorf("unsupported proxy type %q", parts[0])
	}
	port, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid port %q", parts[2])
	}
	p := map[string]interface{}{"name": strings.TrimSpace(name), "type": typ, "server": parts[1], "port": port}
	if len(parts) > 3 && typ == "ss" {
		p["cipher"] = parts[3]
	}
	if len(parts) > 4 && typ == "ss" && !strings.Contains(parts[4], "=") {
		p["password"] = strings.Trim(parts[4], "\"")
	}
	for _, part := range parts[3:] {
		if k, v, ok := strings.Cut(part, "="); ok {
			k = strings.TrimSpace(k)
			v = strings.Trim(strings.TrimSpace(v), "\"")
			switch k {
			case "password":
				p["password"] = v
			case "uuid":
				p["uuid"] = v
			case "sni", "servername":
				p["servername"] = v
			case "skip-cert-verify":
				p[k] = strings.EqualFold(v, "true")
			case "over-tls", "tls":
				p["tls"] = strings.EqualFold(v, "true")
			case "encrypt-method", "method":
				p["cipher"] = v
			case "alterId":
				p["alterId"] = v
			}
		}
	}
	return p, nil
}
func parseGroup(line string) (map[string]interface{}, error) {
	name, value, ok := strings.Cut(line, "=")
	if !ok {
		return nil, fmt.Errorf("expected name = group")
	}
	parts := split(value)
	if len(parts) == 0 {
		return nil, fmt.Errorf("missing group type")
	}
	typ := strings.ToLower(parts[0])
	if typ == "url-test" {
		typ = "url-test"
	}
	g := map[string]interface{}{"name": strings.TrimSpace(name), "type": typ}
	var members []interface{}
	for _, item := range parts[1:] {
		if !strings.Contains(item, "=") {
			members = append(members, item)
		}
	}
	g["proxies"] = members
	return g, nil
}
func parseRemoteRule(line string) (string, map[string]interface{}, string, error) {
	parts := split(line)
	if len(parts) == 0 || parts[0] == "" {
		return "", nil, "", fmt.Errorf("missing URL")
	}
	name, policy := "Remote", "DIRECT"
	for _, p := range parts[1:] {
		if k, v, ok := strings.Cut(p, "="); ok {
			if k == "tag" {
				name = v
			}
			if k == "policy" {
				policy = v
			}
		}
	}
	return name, map[string]interface{}{"type": "http", "behavior": "classical", "url": parts[0], "path": "./ruleset/" + name}, "RULE-SET," + name + "," + policy, nil
}
func normalizeRule(line string) string {
	parts := split(line)
	if len(parts) > 0 && strings.EqualFold(parts[0], "FINAL") {
		parts[0] = "MATCH"
	}
	return strings.Join(parts, ",")
}
func split(s string) []string {
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}
