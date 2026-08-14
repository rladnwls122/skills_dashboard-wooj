package rules

// WAFv2 TextTransformations, ported from src/lib/server/ruletransform.ts.
// Every type AWS accepts is handled except MD5, whose output is raw binary no
// pasted SearchString can express — that one is reported by name.

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type TransformResult struct {
	OK    bool
	Value string
	Type  string // the transform that stopped evaluation, when !OK
}

var htmlEntities = map[string]string{
	"&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": `"`, "&apos;": "'", "&nbsp;": " ",
}

func codePoint(n int64) (string, bool) {
	if n < 0 || n > 0x10ffff {
		return "", false
	}
	return string(rune(n)), true
}

var (
	namedEntityRe = regexp.MustCompile(`(?i)&(?:lt|gt|amp|quot|apos|nbsp);`)
	decEntityRe   = regexp.MustCompile(`&#([0-9]+);?`)
	hexEntityRe   = regexp.MustCompile(`(?i)&#x([0-9a-f]+);?`)
)

func htmlEntityDecode(s string) string {
	s = namedEntityRe.ReplaceAllStringFunc(s, func(m string) string {
		if v, ok := htmlEntities[strings.ToLower(m)]; ok {
			return v
		}
		return m
	})
	s = decEntityRe.ReplaceAllStringFunc(s, func(m string) string {
		d := decEntityRe.FindStringSubmatch(m)[1]
		n, err := strconv.ParseInt(d, 10, 64)
		if err != nil {
			return m
		}
		if v, ok := codePoint(n); ok {
			return v
		}
		return m
	})
	return hexEntityRe.ReplaceAllStringFunc(s, func(m string) string {
		h := hexEntityRe.FindStringSubmatch(m)[1]
		n, err := strconv.ParseInt(h, 16, 64)
		if err != nil {
			return m
		}
		if v, ok := codePoint(n); ok {
			return v
		}
		return m
	})
}

func urlDecode(s string) string {
	// A malformed percent-escape decodes to itself in WAF; keep the raw value.
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

var pctURe = regexp.MustCompile(`(?i)%u([0-9a-f]{4})`)

func urlDecodeUni(s string) string {
	return pctURe.ReplaceAllStringFunc(urlDecode(s), func(m string) string {
		n, _ := strconv.ParseInt(pctURe.FindStringSubmatch(m)[1], 16, 64)
		if v, ok := codePoint(n); ok {
			return v
		}
		return m
	})
}

func normalizePathT(s string) string {
	segs := []string{}
	for _, seg := range strings.Split(s, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
		default:
			segs = append(segs, seg)
		}
	}
	trailing := ""
	if len(s) > 1 && strings.HasSuffix(s, "/") && len(segs) > 0 {
		trailing = "/"
	}
	return "/" + strings.Join(segs, "/") + trailing
}

var b64StrictRe = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

func base64DecodeT(s string, lenient bool) string {
	var t string
	if lenient {
		var b strings.Builder
		for _, r := range s {
			if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' ||
				r == '+' || r == '/' || r == '=' {
				b.WriteRune(r)
			}
		}
		t = b.String()
		if t == "" {
			return s
		}
	} else {
		t = strings.NewReplacer("\r", "", "\n", "").Replace(s)
		// WAF leaves an undecodable value alone.
		if t == "" || len(t)%4 != 0 || !b64StrictRe.MatchString(t) {
			return s
		}
	}
	pad := strings.TrimRight(t, "=")
	if d, err := base64.RawStdEncoding.DecodeString(pad); err == nil {
		return string(d)
	}
	return s
}

func hexDecodeT(s string) string {
	t := strings.TrimSpace(s)
	if t == "" || len(t)%2 != 0 {
		return s
	}
	if d, err := hex.DecodeString(t); err == nil {
		return string(d)
	}
	return s
}

var sqlHexRe = regexp.MustCompile(`\b0x((?:[0-9a-fA-F]{2})+)\b`)

// SQL hex literals: 0x646f67 -> dog
func sqlHexDecode(s string) string {
	return sqlHexRe.ReplaceAllStringFunc(s, func(m string) string {
		h := sqlHexRe.FindStringSubmatch(m)[1]
		if d, err := hex.DecodeString(h); err == nil {
			return string(d)
		}
		return m
	})
}

var escapeChars = map[string]string{
	"a": "\x07", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
	`\`: `\`, "?": "?", "'": "'", `"`: `"`,
}

var (
	escURe    = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	escXRe    = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	escORe    = regexp.MustCompile(`\\([0-7]{1,3})`)
	escCRe    = regexp.MustCompile(`\\([abfnrtv\\?'"])`)
	commentRe = regexp.MustCompile(`(?s)/\*.*?(\*/|$)`)
	wsRe      = regexp.MustCompile(`\s+`)
)

func replCP(re *regexp.Regexp, base int) func(string) string {
	return func(m string) string {
		n, _ := strconv.ParseInt(re.FindStringSubmatch(m)[1], base, 64)
		if v, ok := codePoint(n); ok {
			return v
		}
		return m
	}
}

func escapeSeqDecode(s string) string {
	s = escURe.ReplaceAllStringFunc(s, replCP(escURe, 16))
	s = escXRe.ReplaceAllStringFunc(s, replCP(escXRe, 16))
	s = escORe.ReplaceAllStringFunc(s, replCP(escORe, 8))
	return escCRe.ReplaceAllStringFunc(s, func(m string) string {
		c := escCRe.FindStringSubmatch(m)[1]
		if v, ok := escapeChars[c]; ok {
			return v
		}
		return m
	})
}

var (
	cssContRe = regexp.MustCompile(`\\\r?\n`)
	cssHexRe  = regexp.MustCompile(`\\([0-9a-fA-F]{1,6})[ \t]?`)
	cssAnyRe  = regexp.MustCompile(`\\([^\r\n])`)
)

// CSS escapes: \3c -> "<", "\<newline>" is a line continuation, "\x" -> "x".
func cssDecode(s string) string {
	s = cssContRe.ReplaceAllString(s, "")
	s = cssHexRe.ReplaceAllStringFunc(s, replCP(cssHexRe, 16))
	return cssAnyRe.ReplaceAllString(s, "$1")
}

var (
	jsBraceRe = regexp.MustCompile(`\\u\{([0-9a-fA-F]{1,6})\}`)
	jsCRe     = regexp.MustCompile(`\\([bfnrtv0'"\\/])`)
)

func jsDecode(s string) string {
	s = jsBraceRe.ReplaceAllStringFunc(s, replCP(jsBraceRe, 16))
	s = escURe.ReplaceAllStringFunc(s, replCP(escURe, 16))
	s = escXRe.ReplaceAllStringFunc(s, replCP(escXRe, 16))
	s = escORe.ReplaceAllStringFunc(s, replCP(escORe, 8))
	return jsCRe.ReplaceAllStringFunc(s, func(m string) string {
		c := jsCRe.FindStringSubmatch(m)[1]
		if c == "0" {
			return "\x00"
		}
		if v, ok := escapeChars[c]; ok {
			return v
		}
		return c
	})
}

func utf8ToUnicode(s string) string {
	var out strings.Builder
	for _, ch := range s {
		if ch > 0x7f {
			out.WriteString("%u")
			h := strconv.FormatInt(int64(ch), 16)
			for len(h) < 4 {
				h = "0" + h
			}
			out.WriteString(h)
		} else {
			out.WriteRune(ch)
		}
	}
	return out.String()
}

// AWS CMD_LINE: drop \ " ' ^, collapse whitespace to one space, lowercase.
func cmdLine(s string) string {
	s = strings.NewReplacer(`\`, "", `"`, "", "'", "", "^", "").Replace(s)
	return strings.ToLower(strings.TrimSpace(wsRe.ReplaceAllString(s, " ")))
}

func transformOne(value, typ string) (string, bool) {
	switch typ {
	case "NONE":
		return value, true
	case "LOWERCASE":
		return strings.ToLower(value), true
	case "TRIM":
		return strings.TrimSpace(value), true
	case "COMPRESS_WHITE_SPACE":
		return wsRe.ReplaceAllString(value, " "), true
	case "REMOVE_NULLS":
		return strings.ReplaceAll(value, "\x00", ""), true
	case "REPLACE_NULLS":
		return strings.ReplaceAll(value, "\x00", " "), true
	case "URL_DECODE":
		return urlDecode(value), true
	case "URL_DECODE_UNI":
		return urlDecodeUni(value), true
	case "HTML_ENTITY_DECODE":
		return htmlEntityDecode(value), true
	case "BASE64_DECODE":
		return base64DecodeT(value, false), true
	case "BASE64_DECODE_EXT":
		return base64DecodeT(value, true), true
	case "HEX_DECODE":
		return hexDecodeT(value), true
	case "SQL_HEX_DECODE":
		return sqlHexDecode(value), true
	case "REPLACE_COMMENTS":
		return commentRe.ReplaceAllString(value, " "), true
	case "ESCAPE_SEQ_DECODE":
		return escapeSeqDecode(value), true
	case "CSS_DECODE":
		return cssDecode(value), true
	case "JS_DECODE":
		return jsDecode(value), true
	case "UTF8_TO_UNICODE":
		return utf8ToUnicode(value), true
	case "NORMALIZE_PATH":
		return normalizePathT(value), true
	case "NORMALIZE_PATH_WIN":
		return normalizePathT(strings.ReplaceAll(value, `\`, "/")), true
	case "CMD_LINE":
		return cmdLine(value), true
	default:
		// MD5 lands here on purpose: its output is binary, so no pasted
		// SearchString could be compared against it honestly.
		return "", false
	}
}

func ApplyTransforms(value string, transforms any) TransformResult {
	list, _ := transforms.([]any)
	type tf struct {
		priority float64
		typ      string
	}
	ordered := []tf{}
	for _, t := range list {
		rec, ok := t.(map[string]any)
		if !ok {
			continue
		}
		p, _ := rec["Priority"].(float64)
		typ, _ := rec["Type"].(string)
		ordered = append(ordered, tf{p, typ})
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].priority < ordered[j].priority })

	out := value
	for _, t := range ordered {
		next, ok := transformOne(out, t.typ)
		if !ok {
			typ := t.typ
			if typ == "" {
				typ = "(이름 없는 변환)"
			}
			return TransformResult{OK: false, Type: typ}
		}
		out = next
	}
	return TransformResult{OK: true, Value: out}
}
