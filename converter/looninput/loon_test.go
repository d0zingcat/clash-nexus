package looninput

import (
	"strings"
	"testing"
)

func TestParsePreservesPositionalCredentialsAndGroupHealthCheckOptions(t *testing.T) {
	config, _, err := Parse([]byte("[Proxy]\nV = VMess, v.example, 443, uuid-v, over-tls=true\nT = Trojan, t.example, 443, secret\n[Proxy Group]\nAuto = url-test, V, T, url=http://www.gstatic.com/generate_204, interval=300, tolerance=50\n"))
	if err != nil {
		t.Fatal(err)
	}
	proxies := config["proxies"].([]interface{})
	if proxies[0].(map[string]interface{})["uuid"] != "uuid-v" {
		t.Fatalf("vmess = %#v", proxies[0])
	}
	if proxies[1].(map[string]interface{})["password"] != "secret" {
		t.Fatalf("trojan = %#v", proxies[1])
	}
	group := config["proxy-groups"].([]interface{})[0].(map[string]interface{})
	if group["url"] == nil || group["interval"] != 300 || group["tolerance"] != 50 {
		t.Fatalf("group = %#v", group)
	}
}

func TestParseWarnsForUnmappedSupportedSectionParameters(t *testing.T) {
	_, warnings, err := Parse([]byte("[Proxy]\nV = VMess, v.example, 443, uuid-v, unknown-proxy=value\n[Proxy Group]\nAuto = select, V, unknown-group=value\n[Remote Rule]\nhttps://example.com/rules.list, tag=Rules, unknown-rule=value\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 3 {
		t.Fatalf("warnings = %#v", warnings)
	}
	for _, want := range []string{"[Proxy] unsupported parameter: unknown-proxy", "[Proxy Group] unsupported parameter: unknown-group", "[Remote Rule] unsupported parameter: unknown-rule"} {
		found := false
		for _, warning := range warnings {
			if strings.Contains(warning, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("warnings = %#v, missing %q", warnings, want)
		}
	}
}
