package awsx

// The one door into the WebACL: apply, promote, demote, remove.
//
// `action` is what the rule should be doing after the call — "COUNT", "BLOCK",
// or empty to take it out of the WebACL entirely. The rule is keyed by its
// Name, so promoting is "put it back at the other action" and there is no
// separate update path that could disagree with the create path.
//
// Ported from setRuleAction in waf.ts.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/aws/smithy-go"
)

type RuleUpdate struct {
	RuleName string
	// The WebACL's rule list as it stood before the change, serialized. It is
	// what a rollback replays.
	PriorRules string
}

// ParseRuleDoc reads the pasted rule and reports what cannot be applied.
// Exported so the caller can reject before touching AWS at all.
func ParseRuleDoc(ruleJson string, removing bool) (map[string]any, string, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(ruleJson), &doc); err != nil {
		return nil, "", fmt.Errorf("규칙 JSON 을 파싱할 수 없습니다: %w", err)
	}
	name, _ := doc["Name"].(string)
	if strings.TrimSpace(name) == "" {
		return nil, "", errors.New("규칙에 Name 이 없습니다.")
	}
	if !removing {
		// The assembler prints "<set-ARN>" where the operator has to paste the
		// ARN of the regex pattern set they created. Applying it unchanged
		// fails inside AWS with a validation error that names nothing about
		// what to do next.
		if strings.Contains(ruleJson, "-ARN>") {
			return nil, "", errors.New("규칙에 ARN 자리표시자가 남아 있습니다 — 정규식 패턴 세트를 먼저 만들고 그 ARN 을 채우세요.")
		}
		if _, ok := doc["Statement"]; !ok {
			return nil, "", errors.New("규칙에 Statement 가 없습니다.")
		}
		// A sandbox document (RegexPatternSets + Rules) is not a rule and AWS
		// would reject it with a schema error the screen cannot explain.
		if _, ok := doc["RegexPatternSets"]; ok {
			return nil, "", errors.New("샌드박스용 문서(RegexPatternSets 포함)입니다 — 콘솔용 규칙 JSON 을 붙여넣으세요.")
		}
	}
	return doc, name, nil
}

// SetRuleAction writes the rule into the WebACL at the action given, or removes
// it when action is empty.
func (a *AWS) SetRuleAction(ctx context.Context, ruleJson, action string) (RuleUpdate, error) {
	removing := action == ""
	if !removing && action != "COUNT" && action != "BLOCK" {
		return RuleUpdate{}, fmt.Errorf("알 수 없는 동작: %s (COUNT · BLOCK · 제거만 가능)", action)
	}
	doc, ruleName, err := ParseRuleDoc(ruleJson, removing)
	if err != nil {
		return RuleUpdate{}, err
	}

	attempt := func() (RuleUpdate, error) {
		client, err := a.wafClient(ctx, a.Settings.WafRegion())
		if err != nil {
			return RuleUpdate{}, err
		}
		// The write-only handle: UpdateWebACL below replaces the whole rule
		// list, so it must never run against the WebACL the read fallback
		// guessed at. A refusal here costs one corrected setting; the guess
		// costs someone else's ACL.
		h, err := a.getAclHandleForWrite(ctx)
		if err != nil {
			return RuleUpdate{}, err
		}
		prior := h.webACL.Rules
		kept := make([]waftypes.Rule, 0, len(prior)+1)
		for _, r := range prior {
			if aws.ToString(r.Name) != ruleName {
				kept = append(kept, r)
			}
		}
		if !removing {
			// The action is set here rather than trusted from the pasted JSON:
			// the button the operator pressed is what decides, and a rule
			// pasted with Block inside it must not promote itself.
			doc["Action"] = map[string]any{action2key(action): map[string]any{}}
			rule, err := decodeRule(doc)
			if err != nil {
				return RuleUpdate{}, err
			}
			kept = append(kept, rule)
		}

		priorJSON, err := encodeRules(prior)
		if err != nil {
			return RuleUpdate{}, err
		}
		_, err = client.UpdateWebACL(ctx, &wafv2.UpdateWebACLInput{
			Name:                 h.webACL.Name,
			Id:                   h.webACL.Id,
			Scope:                waftypes.Scope(a.Settings.WafScope()),
			DefaultAction:        h.webACL.DefaultAction,
			Description:          h.webACL.Description,
			VisibilityConfig:     h.webACL.VisibilityConfig,
			CustomResponseBodies: h.webACL.CustomResponseBodies,
			Rules:                kept,
			LockToken:            aws.String(h.lockToken),
		})
		if err != nil {
			return RuleUpdate{}, err
		}
		return RuleUpdate{RuleName: ruleName, PriorRules: priorJSON}, nil
	}

	out, err := attempt()
	if err != nil && isLockConflict(err) {
		// Someone else (the console, the other operator) changed the ACL between
		// our read and our write. Re-reading gives a fresh lock token; a second
		// failure is a real conflict and is surfaced.
		return attempt()
	}
	return out, err
}

func action2key(action string) string {
	if action == "BLOCK" {
		return "Block"
	}
	return "Count"
}

func isLockConflict(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode() == "WAFOptimisticLockException"
	}
	return strings.Contains(err.Error(), "WAFOptimisticLockException")
}

// decodeRule turns the operator's JSON into the SDK's Rule. The field names of
// the generated structs are the console's field names (Name, Priority,
// Statement, …), so the document is re-marshalled through them rather than
// mapped field by field — a rule nests statements arbitrarily deep and a
// hand-written walk would silently drop what it does not know.
func decodeRule(doc map[string]any) (waftypes.Rule, error) {
	raw, err := json.Marshal(encodeBinaryFields(doc))
	if err != nil {
		return waftypes.Rule{}, err
	}
	var rule waftypes.Rule
	if err := json.Unmarshal(raw, &rule); err != nil {
		return waftypes.Rule{}, fmt.Errorf("규칙 구조를 WAFv2 규칙으로 읽을 수 없습니다: %w", err)
	}
	if rule.Name == nil || rule.Statement == nil || rule.VisibilityConfig == nil {
		return waftypes.Rule{}, errors.New("규칙에 Name · Statement · VisibilityConfig 가 모두 있어야 합니다.")
	}
	return rule, nil
}

// SearchString is []byte in the SDK and a plain string in every console export
// and every document this dashboard prints. encoding/json reads []byte as
// base64, so the literal is encoded on the way in — without this a
// ByteMatchStatement pasted from the console fails as "illegal base64 data",
// which says nothing about what to fix.
func encodeBinaryFields(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			if k == "SearchString" {
				if s, ok := child.(string); ok {
					out[k] = base64.StdEncoding.EncodeToString([]byte(s))
					continue
				}
			}
			out[k] = encodeBinaryFields(child)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = encodeBinaryFields(child)
		}
		return out
	default:
		return v
	}
}

// encodeRules serializes the rule list as it stood before the change. It is
// stored with the history row as the record of what was replaced; binary fields
// come out base64-encoded, which is the SDK's own shape and not the console's.
func encodeRules(rules []waftypes.Rule) (string, error) {
	if rules == nil {
		rules = []waftypes.Rule{}
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
