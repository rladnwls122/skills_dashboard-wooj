// The one door into the WebACL: apply, promote, demote, remove.
//
// `action` is what the rule should be doing after the call — "COUNT", "BLOCK",
// or empty to take it out of the WebACL entirely. The rule is keyed by its Name,
// so promoting is "put it back at the other action" and there is no separate
// update path that could disagree with the create path.

import { UpdateWebACLCommand, type Rule, type Scope } from "@aws-sdk/client-wafv2";

import { errCode, errMsg, type AWS } from "./clients.ts";
import { getAclHandleForWrite } from "./waf.ts";

export interface RuleUpdate {
  ruleName: string;
  /**
   * The WebACL's rule list as it stood before the change, serialized. It is what
   * a rollback replays.
   */
  priorRules: string;
}

/**
 * Reads the pasted rule and reports what cannot be applied. Exported so the
 * caller can reject before touching AWS at all.
 */
export function parseRuleDoc(
  ruleJson: string,
  removing: boolean,
): { doc: Record<string, unknown>; name: string } {
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(ruleJson) as Record<string, unknown>;
  } catch (e) {
    throw new Error(`규칙 JSON 을 파싱할 수 없습니다: ${errMsg(e)}`);
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    throw new Error("규칙 JSON 이 객체가 아닙니다.");
  }
  const name = typeof doc.Name === "string" ? doc.Name : "";
  if (name.trim() === "") throw new Error("규칙에 Name 이 없습니다.");

  if (!removing) {
    // The assembler prints "<set-ARN>" where the operator has to paste the ARN
    // of the regex pattern set they created. Applying it unchanged fails inside
    // AWS with a validation error that names nothing about what to do next.
    if (ruleJson.includes("-ARN>")) {
      throw new Error(
        "규칙에 ARN 자리표시자가 남아 있습니다 — 정규식 패턴 세트를 먼저 만들고 그 ARN 을 채우세요.",
      );
    }
    if (!("Statement" in doc)) throw new Error("규칙에 Statement 가 없습니다.");
    // A sandbox document (RegexPatternSets + Rules) is not a rule and AWS would
    // reject it with a schema error the screen cannot explain.
    if ("RegexPatternSets" in doc) {
      throw new Error("샌드박스용 문서(RegexPatternSets 포함)입니다 — 콘솔용 규칙 JSON 을 붙여넣으세요.");
    }
  }
  return { doc, name };
}

/**
 * Writes the rule into the WebACL at the action given, or removes it when action
 * is empty.
 */
export async function setRuleAction(
  a: AWS,
  ruleJson: string,
  action: string,
): Promise<RuleUpdate> {
  const removing = action === "";
  if (!removing && action !== "COUNT" && action !== "BLOCK") {
    throw new Error(`알 수 없는 동작: ${action} (COUNT · BLOCK · 제거만 가능)`);
  }
  const { doc, name: ruleName } = parseRuleDoc(ruleJson, removing);

  const attempt = async (): Promise<RuleUpdate> => {
    const client = a.wafClient(a.settings.wafRegion());
    const h = await getAclHandleForWrite(a);
    const prior = h.webAcl.Rules ?? [];
    const kept = prior.filter((r) => r.Name !== ruleName);

    if (!removing) {
      // The action is set here rather than trusted from the pasted JSON: the
      // button the operator pressed is what decides, and a rule pasted with
      // Block inside it must not promote itself.
      doc.Action = { [action === "BLOCK" ? "Block" : "Count"]: {} };
      kept.push(decodeRule(doc));
    }

    const priorJson = encodeRules(prior);
    await client.send(
      new UpdateWebACLCommand({
        Name: h.webAcl.Name,
        Id: h.webAcl.Id,
        Scope: a.settings.wafScope() as Scope,
        DefaultAction: h.webAcl.DefaultAction,
        Description: h.webAcl.Description,
        VisibilityConfig: h.webAcl.VisibilityConfig,
        CustomResponseBodies: h.webAcl.CustomResponseBodies,
        Rules: kept,
        LockToken: h.lockToken,
      }),
    );
    return { ruleName, priorRules: priorJson };
  };

  try {
    return await attempt();
  } catch (e) {
    if (isLockConflict(e)) {
      // Someone else (the console, the other operator) changed the ACL between
      // our read and our write. Re-reading gives a fresh lock token; a second
      // failure is a real conflict and is surfaced.
      return attempt();
    }
    throw e;
  }
}

function isLockConflict(e: unknown): boolean {
  return errCode(e) === "WAFOptimisticLockException" || errMsg(e).includes("WAFOptimisticLockException");
}

/**
 * Turns the operator's JSON into the SDK's Rule. The console's field names are
 * the SDK's field names (Name, Priority, Statement, …), so the document is
 * handed over as-is rather than mapped field by field — a rule nests statements
 * arbitrarily deep and a hand-written walk would silently drop what it does not
 * know.
 */
function decodeRule(doc: Record<string, unknown>): Rule {
  const rule = encodeBinaryFields(doc) as Rule;
  if (!rule.Name || !rule.Statement || !rule.VisibilityConfig) {
    throw new Error("규칙에 Name · Statement · VisibilityConfig 가 모두 있어야 합니다.");
  }
  return rule;
}

/**
 * SearchString is a Uint8Array in the SDK and a plain string in every console
 * export and every document this dashboard prints. Without this conversion a
 * ByteMatchStatement pasted from the console is serialized as an object of
 * numbered keys and AWS rejects it with a schema error that says nothing about
 * what to fix.
 */
function encodeBinaryFields(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(encodeBinaryFields);
  if (v !== null && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, child] of Object.entries(v as Record<string, unknown>)) {
      if (k === "SearchString" && typeof child === "string") {
        out[k] = Buffer.from(child, "utf8");
        continue;
      }
      out[k] = encodeBinaryFields(child);
    }
    return out;
  }
  return v;
}

/**
 * Serializes the rule list as it stood before the change. It is stored with the
 * history row as the record of what was replaced; binary fields come out
 * base64-encoded, which is the SDK's own wire shape and not the console's.
 */
function encodeRules(rules: Rule[]): string {
  return JSON.stringify(rules, (_key, value: unknown) =>
    value instanceof Uint8Array ? Buffer.from(value).toString("base64") : value,
  );
}
