package converter

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMarshalKeepsAstralCharactersReadable(t *testing.T) {
	v := map[string]interface{}{
		"proxies": []interface{}{
			map[string]interface{}{"name": "🇯🇵 Osaka-Oracle", "server": "example.com", "port": 443},
			map[string]interface{}{"name": "🛑 block", "type": "ss"},
			map[string]interface{}{"name": "日本 东京-01"},
		},
	}
	data, err := Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(data)
	if strings.Contains(got, `\U0001`) {
		t.Errorf("astral escapes leaked into output:\n%s", got)
	}
	for _, want := range []string{"🇯🇵 Osaka-Oracle", "🛑 block", "日本 东京-01"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}

	var back map[string]interface{}
	if err := yaml.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal marshaled output: %v", err)
	}
	names := []string{}
	for _, item := range back["proxies"].([]interface{}) {
		names = append(names, item.(map[string]interface{})["name"].(string))
	}
	want := []string{"🇯🇵 Osaka-Oracle", "🛑 block", "日本 东京-01"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Errorf("round-trip changed names: %q -> %q", want, names)
	}
}

func TestMarshalPreservesLiteralBackslashSequences(t *testing.T) {
	// A source string that merely *looks* like an escape must not be
	// turned into the character it spells. yaml.v3 double-quotes it and
	// doubles the backslash; our scanner consumes "\\" as a unit.
	for _, name := range []string{`foo\U0001F1EFbar`, `\U0001F1EF`, `a\U0001F1EF hello`} {
		v := map[string]interface{}{"name": name}
		data, err := Marshal(v)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if strings.Contains(string(data), "🇯") {
			t.Errorf("literal escape text was decoded for %q:\n%s", name, data)
		}
		var back map[string]interface{}
		if err := yaml.Unmarshal(data, &back); err != nil {
			t.Fatalf("unmarshal for %q: %v", name, err)
		}
		if got := back["name"].(string); got != name {
			t.Errorf("round-trip changed %q to %q", name, got)
		}
	}
}

func TestMarshalKeepsQuotedNamesWithEscapesReadable(t *testing.T) {
	// Quote handling inside double-quoted scalars must not desynchronize
	// the state machine: the emoji in the middle is still decoded.
	v := map[string]interface{}{"name": `he said "hi" 🇯🇵 done`}
	data, err := Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), `\U0001`) {
		t.Errorf("emoji after escaped quote was not decoded:\n%s", data)
	}
	var back map[string]interface{}
	if err := yaml.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := back["name"].(string); got != `he said "hi" 🇯🇵 done` {
		t.Errorf("round-trip changed name to %q", got)
	}
}

func TestMarshalLeavesLegitimateEscapesAlone(t *testing.T) {
	// Control characters are genuinely non-printable; yaml.v3's escapes
	// for them are correct and must survive unchanged.
	v := map[string]interface{}{"name": "a\x01b"}
	plain, err := yaml.Marshal(v)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	fixed, err := Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(fixed) != string(plain) {
		t.Errorf("control-char output changed:\nwant %q\ngot  %q", plain, fixed)
	}
}

func TestDecodeAstralEscapes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`"\U0001F1EF Osaka"`, `"🇯 Osaka"`},
		{`"\U0001f1ef"`, `"🇯"`},                        // lowercase hex decodes too
		{`"a\U0001F1EF\U0001F1F5"`, `"a🇯🇵"`},           // adjacent escapes
		{`"a\U0001F1EF0b"`, `"a\U0001F1EF0b"`},         // 9th hex digit: leave alone
		{`"\U00000041"`, `"\U00000041"`},               // BMP: not our target
		{`"\UFFFFFFFF"`, `"\UFFFFFFFF"`},               // invalid code point
		{`"\U0000D800"`, `"\U0000D800"`},               // surrogate: below U+10000 anyway
		{`"\UFFFF"`, `"\UFFFF"`},                       // \u form untouched
		{`"\x01"`, `"\x01"`},                           // control escape untouched
		{`say \U0001F1EF now`, `say \U0001F1EF now`},   // outside quotes: untouched
		{`"foo\\U0001F1EFbar"`, `"foo\\U0001F1EFbar"`}, // escaped backslash
		{`"say \"ok\" \U0001F1EF"`, `"say \"ok\" 🇯"`},  // escaped quote keeps state
	}
	for _, c := range cases {
		got := string(decodeAstralEscapes([]byte(c.in)))
		if got != c.want {
			t.Errorf("decodeAstralEscapes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDecodeAstralEscapesPreservesFoldedMultilineScalars(t *testing.T) {
	// yaml.v3 wraps long double-quoted scalars across lines; the quote
	// state must stay open so escapes after a fold still decode.
	in := "\"long name with \\U0001F1EF\n    after fold\"\n"
	want := "\"long name with 🇯\n    after fold\"\n"
	if got := string(decodeAstralEscapes([]byte(in))); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
