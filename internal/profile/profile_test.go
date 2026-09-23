package profile

import (
	"strings"
	"testing"
)

func TestComposeMergesSourcesAndOverlay(t *testing.T) {
	p := Profile{Base: "proxies:\n  - {name: base, type: socks5, server: a, port: 1}\nproxy-groups:\n  - name: Main\n    type: select\n    proxies: [base, old]\nrules: [MATCH,Main]\ndns:\n  nameserver: [1.1.1.1]\n  nameserver-policy: {example.com: [1.1.1.1]}\n", DNSAuthority: "second", Sources: []Source{{Name: "first", YAML: "proxies:\n  - {name: node, type: ss, server: b, port: 2}\ndns:\n  nameserver: [8.8.8.8]\n  nameserver-policy: {a.example: [8.8.8.8]}\n"}, {Name: "second", YAML: "proxies:\n  - {name: node2, type: ss, server: c, port: 3}\ndns:\n  nameserver: [9.9.9.9]\n  default-nameserver: [9.9.9.9]\n  nameserver-policy: {example.com: [9.9.9.9]}\n"}}, Overlay: "proxy-groups:\n  - name: Main\n    proxies:\n      remove: [old]\n      append: [node]\n"}
	out, err := Compose(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{"name: base", "name: node", "name: node2", "MATCH,Main", "9.9.9.9", "a.example"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "old") {
		t.Fatalf("removed item remains:\n%s", text)
	}
}

func TestComposeRejectsConflictingNames(t *testing.T) {
	_, err := Compose(Profile{Base: "proxies: [{name: same, type: ss, server: one}]\n", Sources: []Source{{Name: "feed", YAML: "proxies: [{name: same, type: ss, server: two}]\n"}}})
	if err == nil || !strings.Contains(err.Error(), "conflicting proxy") {
		t.Fatalf("error = %v", err)
	}
}

func TestComposeRejectsReplaceCombinedWithAppend(t *testing.T) {
	_, err := Compose(Profile{Base: "proxy-groups: []\n", Overlay: "proxy-groups:\n  replace: []\n  append: []\n"})
	if err == nil {
		t.Fatal("expected incompatible directives to fail")
	}
}
