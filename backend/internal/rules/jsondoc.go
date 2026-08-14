package rules

// A tolerant reader for what an operator actually has on the clipboard, ported
// from src/lib/server/rulejson.ts. Accepts "}{" back-to-back documents, //
// and /* */ comments, and trailing commas — everything string-aware.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type cursor struct {
	text []rune
	i    int
}

// skipString advances past a JSON string literal starting at cur.i (on the
// quote). Returns false when the literal never closes.
func skipString(cur *cursor) bool {
	cur.i++
	for cur.i < len(cur.text) {
		ch := cur.text[cur.i]
		if ch == '\\' {
			cur.i += 2
			continue
		}
		cur.i++
		if ch == '"' {
			return true
		}
	}
	return false
}

var spaceRe = regexp.MustCompile(`^\s$`)

// sanitize removes // and /* */ comments and trailing commas.
func sanitize(text string) string {
	out := []rune{}
	cur := &cursor{text: []rune(text)}

	dropTrailingComma := func() {
		j := len(out) - 1
		for j >= 0 && spaceRe.MatchString(string(out[j])) {
			j--
		}
		if j >= 0 && out[j] == ',' {
			out = append(out[:j], out[j+1:]...)
		}
	}

	for cur.i < len(cur.text) {
		ch := cur.text[cur.i]
		if ch == '"' {
			start := cur.i
			if !skipString(cur) {
				// Unterminated: hand the rest to json.Unmarshal so it reports it.
				out = append(out, cur.text[start:]...)
				break
			}
			out = append(out, cur.text[start:cur.i]...)
			continue
		}
		if ch == '/' && cur.i+1 < len(cur.text) && cur.text[cur.i+1] == '/' {
			for cur.i < len(cur.text) && cur.text[cur.i] != '\n' {
				cur.i++
			}
			continue
		}
		if ch == '/' && cur.i+1 < len(cur.text) && cur.text[cur.i+1] == '*' {
			end := strings.Index(string(cur.text[cur.i+2:]), "*/")
			if end < 0 {
				cur.i = len(cur.text)
			} else {
				cur.i += 2 + end + 2
			}
			continue
		}
		if ch == '}' || ch == ']' {
			dropTrailingComma()
		}
		out = append(out, ch)
		cur.i++
	}
	return string(out)
}

// splitTopLevelValues splits sanitized text into the source of each top-level
// object/array.
func splitTopLevelValues(text string) ([]string, error) {
	values := []string{}
	cur := &cursor{text: []rune(text)}

	for cur.i < len(cur.text) {
		ch := cur.text[cur.i]
		// Between values only whitespace and separating commas are allowed.
		if spaceRe.MatchString(string(ch)) || ch == ',' {
			cur.i++
			continue
		}
		if ch != '{' && ch != '[' {
			return nil, fmt.Errorf(`규칙 JSON을 읽을 수 없음 — %d번째 문자에서 "{" 또는 "["를 기대했는데 "%c"가 나옴`, cur.i+1, ch)
		}

		start := cur.i
		depth := 0
		closed := false
		for cur.i < len(cur.text) {
			c := cur.text[cur.i]
			if c == '"' {
				if !skipString(cur) {
					return nil, fmt.Errorf("규칙 JSON을 읽을 수 없음 — 닫히지 않은 문자열이 있음")
				}
				continue
			}
			if c == '{' || c == '[' {
				depth++
			}
			if c == '}' || c == ']' {
				depth--
			}
			cur.i++
			if depth == 0 {
				closed = true
				break
			}
		}
		if !closed {
			return nil, fmt.Errorf("규칙 JSON을 읽을 수 없음 — 괄호가 닫히지 않음")
		}
		values = append(values, string(cur.text[start:cur.i]))
	}
	return values, nil
}

// ParseJsonDocuments parses one or more JSON documents out of a single pasted
// blob.
func ParseJsonDocuments(text string) ([]any, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, fmt.Errorf("규칙 JSON이 비어 있음")
	}

	// The common case — one well-formed document — never goes near the scanner.
	var one any
	if err := json.Unmarshal([]byte(trimmed), &one); err == nil {
		return []any{one}, nil
	}

	sources, err := splitTopLevelValues(sanitize(trimmed))
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("규칙 JSON에서 읽을 수 있는 값을 찾지 못함")
	}

	out := make([]any, 0, len(sources))
	for i, src := range sources {
		var v any
		if err := json.Unmarshal([]byte(src), &v); err != nil {
			if len(sources) == 1 {
				return nil, fmt.Errorf("규칙 JSON 파싱 실패: %v", err)
			}
			return nil, fmt.Errorf("%d번째 JSON 블록 파싱 실패: %v", i+1, err)
		}
		out = append(out, v)
	}
	return out, nil
}
