package converter

import (
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Marshal serializes v to YAML and restores the astral-plane characters
// (emoji, flag symbols) that yaml.v3 needlessly escapes.
//
// yaml.v3's is_printable() misses 4-byte UTF-8 sequences, so every code
// point >= U+10000 is emitted as a `\UXXXXXXXX` escape inside a
// double-quoted scalar, making names like "🇯🇵 Osaka-Oracle" unreadable in
// generated configs (go-yaml/yaml#737; the bug survives in the successor
// releases go.yaml.in/yaml/v3 v3.0.4 and v4.0.0-rc.6, unfixed). The escapes
// are valid YAML, so this is purely a readability problem, but these configs
// are meant to be read and hand-edited.
//
// Only `\U` escapes for code points >= U+10000 are rewritten, and only
// while inside a double-quoted scalar: the scanner tracks quote state so a
// literal `\U0001F1EF` appearing as plain text in the source is (with
// negligible residual risk, see decodeAstralEscapes) left untouched. The
// emitter's own backslash escaping (`\\`) is consumed as a unit, so the
// source string `\U0001F1EF` marshals back intact. Control-character
// escapes (`\xNN`, `\uNNNN`) are legitimate and stay as written.
func Marshal(v interface{}) ([]byte, error) {
	data, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	return decodeAstralEscapes(data), nil
}

// decodeAstralEscapes replaces `\UXXXXXXXX` sequences in double-quoted
// scalars with their literal UTF-8 encoding.
//
// Quote tracking is deliberately simple: an unescaped `"` opens the scalar
// and the next unescaped `"` closes it. Stray `"` characters inside plain
// or single-quoted scalars can shift that state, but the failure mode is
// benign: a mis-paired state can only suppress decoding (leaving the
// original escape text, i.e. today's cosmetic behavior) or apply it to a
// plain scalar that happens to contain both a `"` and a `\U`-escape-looking
// sequence, which no realistic config does.
func decodeAstralEscapes(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inDoubleQuoted := false
	for i := 0; i < len(data); {
		c := data[i]
		switch {
		case c == '"' && !inDoubleQuoted:
			inDoubleQuoted = true
			out = append(out, c)
			i++
		case c == '"' && inDoubleQuoted:
			inDoubleQuoted = false
			out = append(out, c)
			i++
		case c == '\\' && inDoubleQuoted && i+1 < len(data) && (data[i+1] == '\\' || data[i+1] == '"'):
			// Escaped backslash: consume both so the following "U" cannot
			// open a bogus escape (source text containing a literal \U).
			// Escaped quote: consume both so it cannot close the scalar.
			out = append(out, '\\', data[i+1])
			i += 2
		case c == '\\' && inDoubleQuoted && i+1 < len(data) && data[i+1] == 'U':
			if r, ok := astralEscape(data[i+2:]); ok {
				out = utf8.AppendRune(out, r)
				i += 10 // `\U` + 8 hex digits
			} else {
				out = append(out, c)
				i++
			}
		default:
			out = append(out, c)
			i++
		}
	}
	return out
}

// astralEscape decodes the 8 hex digits following a `\U` marker. It reports
// false unless the digits are valid hex, denote a scalar code point (>=
// U+10000; the emitter never uses `\U` for BMP characters), and are not
// immediately followed by another hex digit (so plain-looking text such as
// `\U0001F1EF0` is left alone).
func astralEscape(b []byte) (rune, bool) {
	if len(b) < 8 || (len(b) > 8 && isHexDigit(b[8])) {
		return 0, false
	}
	var v rune
	for i := 0; i < 8; i++ {
		d, ok := hexValue(b[i])
		if !ok {
			return 0, false
		}
		v = v<<4 | rune(d)
	}
	if v < 0x10000 || v > utf8.MaxRune {
		return 0, false
	}
	return v, true
}

func hexValue(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func isHexDigit(c byte) bool { _, ok := hexValue(c); return ok }
