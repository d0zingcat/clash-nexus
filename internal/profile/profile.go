package profile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

type Source struct {
	Name string `json:"name"`
	YAML string `json:"yaml"`
	URL  string `json:"url,omitempty"`
}
type Profile struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Base         string   `json:"base"`
	Sources      []Source `json:"sources"`
	DNSAuthority string   `json:"dnsAuthority"`
	Overlay      string   `json:"overlay"`
	Token        string   `json:"token"`
	Version      uint64   `json:"version"`
}
type Store struct{ dir string }

func NewStore() (*Store, error) {
	dir := strings.TrimSpace(os.Getenv("CLASH_NEXUS_DATA_DIR"))
	if dir == "" {
		root := os.Getenv("XDG_DATA_HOME")
		if root == "" {
			home, e := os.UserHomeDir()
			if e != nil {
				return nil, e
			}
			root = filepath.Join(home, ".local", "share")
		}
		dir = filepath.Join(root, "clash-nexus")
	}
	if err := os.MkdirAll(filepath.Join(dir, "profiles"), 0700); err != nil {
		return nil, err
	}
	return &Store{dir: filepath.Join(dir, "profiles")}, nil
}
func (s *Store) path(id string) string { return filepath.Join(s.dir, id+".json") }
func validID(id string) bool {
	if id == "" || len(id) > 80 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
func (s *Store) List() ([]Profile, error) {
	files, e := filepath.Glob(filepath.Join(s.dir, "*.json"))
	if e != nil {
		return nil, e
	}
	out := []Profile{}
	for _, f := range files {
		b, e := os.ReadFile(f)
		if e != nil {
			return nil, e
		}
		var p Profile
		if json.Unmarshal(b, &p) == nil {
			p.Token = ""
			out = append(out, p)
		}
	}
	return out, nil
}
func (s *Store) Get(id string) (Profile, error) {
	if !validID(id) {
		return Profile{}, os.ErrNotExist
	}
	b, e := os.ReadFile(s.path(id))
	if e != nil {
		return Profile{}, e
	}
	var p Profile
	e = json.Unmarshal(b, &p)
	return p, e
}
func (s *Store) Save(p Profile) (Profile, error) {
	if strings.TrimSpace(p.Name) == "" {
		return p, errors.New("name is required")
	}
	if p.ID == "" {
		p.ID = randomHex(12)
		p.Token = randomHex(32)
		p.Version = 1
	} else {
		old, e := s.Get(p.ID)
		if e != nil {
			return p, e
		}
		p.Token = old.Token
		p.Version = old.Version + 1
	}
	if _, e := Compose(p); e != nil {
		return p, e
	}
	b, e := json.MarshalIndent(p, "", "  ")
	if e != nil {
		return p, e
	}
	tmp, e := os.CreateTemp(s.dir, ".profile-*")
	if e != nil {
		return p, e
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, e = tmp.Write(b); e == nil {
		e = tmp.Sync()
	}
	ce := tmp.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(name, s.path(p.ID))
	}
	return p, e
}
func (s *Store) Delete(id string) error {
	if !validID(id) {
		return os.ErrNotExist
	}
	return os.Remove(s.path(id))
}
func randomHex(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }

func parse(raw string) (map[string]interface{}, error) {
	var v interface{}
	if err := yaml.Unmarshal([]byte(raw), &v); err != nil {
		return nil, err
	}
	m, ok := normalize(v).(map[string]interface{})
	if !ok {
		return nil, errors.New("configuration must be a YAML mapping")
	}
	return m, nil
}
func normalize(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		m := map[string]interface{}{}
		for k, v := range x {
			m[k] = normalize(v)
		}
		return m
	case map[interface{}]interface{}:
		m := map[string]interface{}{}
		for k, v := range x {
			m[fmt.Sprint(k)] = normalize(v)
		}
		return m
	case []interface{}:
		a := make([]interface{}, len(x))
		for i, v := range x {
			a[i] = normalize(v)
		}
		return a
	default:
		return v
	}
}
func Compose(p Profile) ([]byte, error) {
	base, e := parse(p.Base)
	if e != nil {
		return nil, fmt.Errorf("invalid Base YAML: %w", e)
	}
	out := base
	proxies := []interface{}{}
	providers := map[string]interface{}{}
	policy := map[string]interface{}{}
	addNamed := func(dst *[]interface{}, value interface{}, kind string) error {
		list, ok := value.([]interface{})
		if !ok {
			return fmt.Errorf("%s must be a list", kind)
		}
		for _, item := range list {
			obj, ok := item.(map[string]interface{})
			if !ok {
				return fmt.Errorf("%s entries must be mappings", kind)
			}
			name, ok := obj["name"].(string)
			if !ok || name == "" {
				return fmt.Errorf("%s entry has no name", kind)
			}
			found := false
			for _, existing := range *dst {
				em := existing.(map[string]interface{})
				if em["name"] == name {
					if !reflect.DeepEqual(em, obj) {
						return fmt.Errorf("conflicting %s %q", kind, name)
					}
					found = true
					break
				}
			}
			if !found {
				*dst = append(*dst, obj)
			}
		}
		return nil
	}
	if v, ok := base["proxies"]; ok {
		if e = addNamed(&proxies, v, "proxy"); e != nil {
			return nil, e
		}
	}
	if raw, ok := base["proxy-providers"]; ok {
		if _, valid := raw.(map[string]interface{}); !valid {
			return nil, errors.New("proxy-providers must be a mapping")
		}
	}
	for k, v := range asMap(base["proxy-providers"]) {
		providers[k] = v
	}
	if d, ok := asMap(base["dns"])["nameserver-policy"]; ok {
		for k, v := range asMap(d) {
			policy[k] = v
		}
	}
	all := append([]Source(nil), p.Sources...)
	parsed := make([]map[string]interface{}, len(all))
	seenSources := map[string]bool{}
	for i, src := range all {
		if strings.TrimSpace(src.Name) == "" {
			return nil, fmt.Errorf("source %d has no name", i+1)
		}
		if seenSources[src.Name] {
			return nil, fmt.Errorf("duplicate source name %q", src.Name)
		}
		seenSources[src.Name] = true
		m, e := parse(src.YAML)
		if e != nil {
			return nil, fmt.Errorf("invalid source %q YAML: %w", src.Name, e)
		}
		parsed[i] = m
		if v, ok := m["proxies"]; ok {
			if e = addNamed(&proxies, v, "proxy"); e != nil {
				return nil, fmt.Errorf("source %q: %w", src.Name, e)
			}
		}
		if raw, ok := m["proxy-providers"]; ok {
			if _, valid := raw.(map[string]interface{}); !valid {
				return nil, fmt.Errorf("source %q: proxy-providers must be a mapping", src.Name)
			}
		}
		for k, v := range asMap(m["proxy-providers"]) {
			if old, ok := providers[k]; ok && !reflect.DeepEqual(old, v) {
				return nil, fmt.Errorf("conflicting proxy-provider %q", k)
			}
			providers[k] = v
		}
		for k, v := range asMap(asMap(m["dns"])["nameserver-policy"]) {
			policy[k] = v
		}
	}
	if len(proxies) > 0 {
		out["proxies"] = proxies
	}
	if len(providers) > 0 {
		out["proxy-providers"] = providers
	}
	dns := asMap(out["dns"])
	if dns == nil {
		dns = map[string]interface{}{}
	}
	if len(policy) > 0 {
		dns["nameserver-policy"] = policy
	}
	if p.DNSAuthority != "base" && p.DNSAuthority != "" {
		found := false
		for i, src := range all {
			if src.Name == p.DNSAuthority || fmt.Sprint(i) == p.DNSAuthority {
				authority := asMap(parsed[i]["dns"])
				for _, k := range []string{"nameserver", "default-nameserver"} {
					if v, ok := authority[k]; ok {
						dns[k] = v
					} else {
						delete(dns, k)
					}
				}
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("DNS authority %q is not a source", p.DNSAuthority)
		}
	}
	if len(dns) > 0 {
		out["dns"] = dns
	}
	if strings.TrimSpace(p.Overlay) != "" {
		ov, e := parse(p.Overlay)
		if e != nil {
			return nil, fmt.Errorf("invalid overlay YAML: %w", e)
		}
		if e = mergeMap(out, ov); e != nil {
			return nil, e
		}
	}
	b, e := yaml.Marshal(out)
	return b, e
}
func asMap(v interface{}) map[string]interface{} { m, _ := v.(map[string]interface{}); return m }
func mergeMap(dst, ov map[string]interface{}) error {
	for k, v := range ov {
		if v == nil {
			delete(dst, k)
			continue
		}
		if incoming, ok := v.([]interface{}); ok {
			if current, exists := dst[k].([]interface{}); exists {
				merged, handled, err := mergeNamedList(current, incoming)
				if err != nil {
					return err
				}
				if handled {
					dst[k] = merged
					continue
				}
				return fmt.Errorf("overlay %s must use append, remove, or replace to change a list", k)
			}
			dst[k] = v
			continue
		}
		if vm, ok := v.(map[string]interface{}); ok {
			_, appendList := vm["append"]
			_, removeList := vm["remove"]
			_, replaceList := vm["replace"]
			if appendList || removeList || replaceList {
				if replaceList && (appendList || removeList) {
					return fmt.Errorf("overlay %s replace cannot be combined with append or remove", k)
				}
				for action := range vm {
					if action != "append" && action != "remove" && action != "replace" {
						return fmt.Errorf("overlay %s mixes list directives and mapping keys", k)
					}
				}
				if replaceList {
					if err := mergeListDirective(dst, k, "replace", vm["replace"]); err != nil {
						return err
					}
					continue
				}
				if removeList {
					if err := mergeListDirective(dst, k, "remove", vm["remove"]); err != nil {
						return err
					}
				}
				if appendList {
					if err := mergeListDirective(dst, k, "append", vm["append"]); err != nil {
						return err
					}
				}
				continue
			}
			old, ok := dst[k].(map[string]interface{})
			if !ok {
				old = map[string]interface{}{}
			}
			if e := mergeMap(old, vm); e != nil {
				return e
			}
			dst[k] = old
		} else {
			dst[k] = v
		}
	}
	return nil
}
func mergeNamedList(current, incoming []interface{}) ([]interface{}, bool, error) {
	if len(incoming) == 0 {
		return incoming, false, nil
	}
	for _, item := range incoming {
		m, ok := item.(map[string]interface{})
		if !ok {
			return incoming, false, nil
		}
		if _, ok = m["name"]; !ok {
			return incoming, false, nil
		}
	}
	out := append([]interface{}{}, current...)
	for _, item := range incoming {
		m := item.(map[string]interface{})
		name := m["name"]
		found := false
		for i, old := range out {
			om, ok := old.(map[string]interface{})
			if ok && om["name"] == name {
				if err := mergeMap(om, m); err != nil {
					return nil, true, err
				}
				out[i] = om
				found = true
				break
			}
		}
		if !found {
			out = append(out, item)
		}
	}
	return out, true, nil
}
func mergeListDirective(dst map[string]interface{}, k, op string, v interface{}) error {
	items, ok := v.([]interface{})
	if !ok {
		return fmt.Errorf("overlay %s.%s must be a list", k, op)
	}
	if op == "replace" {
		dst[k] = items
		return nil
	}
	current, _ := dst[k].([]interface{})
	if op == "remove" {
		out := current[:0]
		for _, x := range current {
			remove := false
			for _, y := range items {
				if reflect.DeepEqual(x, y) {
					remove = true
					break
				}
			}
			if !remove {
				out = append(out, x)
			}
		}
		dst[k] = out
		return nil
	}
	for _, x := range items {
		exists := false
		for _, y := range current {
			if reflect.DeepEqual(x, y) {
				exists = true
				break
			}
		}
		if !exists {
			current = append(current, x)
		}
	}
	dst[k] = current
	return nil
}
