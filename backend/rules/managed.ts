// Local approximation of the AWS managed rule groups. What is reproduced is the
// documented intent of their best-known rules; a group whose decision genuinely
// depends on AWS-side data returns UNKNOWN rather than a guess.

import { looksLikeSqli, looksLikeXss, SENSITIVITY_HIGH } from "./injection.ts";
import { isPrivateIp, type NormalizedRequest } from "./request.ts";
import { CATEGORY_RECON, CATEGORY_SCANNER, classifyUa } from "./threatsig.ts";
import { VERDICT_FALSE, VERDICT_TRUE, VERDICT_UNKNOWN, type Verdict3 } from "./verdict.ts";

export interface ManagedVerdict {
  matched: Verdict3;
  /** Names of the approximated sub-rules that fired. */
  rules: string[];
  /** Labels the group would add to the request. */
  labels: string[];
  /** Why the group could not be decided, when matched === VERDICT_UNKNOWN. */
  note: string;
}

interface SubRule {
  name: string;
  test: (r: NormalizedRequest) => boolean;
}

export function argValues(r: NormalizedRequest): string[] {
  return r.args.map((a) => a.value);
}

function cookieValues(r: NormalizedRequest): string[] {
  return [...r.cookies.values()];
}

function uaOf(r: NormalizedRequest): string {
  return r.headers.get("user-agent") ?? "";
}

/** The surfaces AWS's managed groups inspect for injection payloads. */
function injectionSurfaces(r: NormalizedRequest): string[] {
  return [r.path, r.query, ...argValues(r), r.body, ...cookieValues(r), uaOf(r)].filter(
    (s) => s !== "",
  );
}

function anyMatch(values: string[], re: RegExp): boolean {
  return values.some((v) => re.test(v));
}

const TRAVERSAL_RE = /(?:^|[/\\])\.\.(?:[/\\]|$)|%2e%2e[/\\%]/i;
const METADATA_RE = /169\.254\.169\.254|\/latest\/meta-data|\/latest\/api\/token/i;
const RFI_RE = /(?:https?|ftp|php|file|gopher|dict):\/\//i;
const RESTRICTED_EXT_RE = /\.(?:log|ini|bak|backup|old|swp|sql|conf|config|dll|exe)(?:$|[?#])/i;
const LFI_FILE_RE =
  /\/(?:etc\/(?:passwd|shadow|hosts|group)|proc\/self\/(?:environ|cmdline)|windows\/win\.ini|boot\.ini)\b/i;
const SHELL_RE =
  /(?:;|\||&&|\$\(|`)\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|netcat|bash|sh|python|perl|chmod|rm)\b/i;
const SHELLSHOCK_RE = /\(\s*\)\s*\{/;
const WINDOWS_RE =
  /(?:powershell(?:\.exe)?\b|cmd\.exe\b|%SystemRoot%|\bnet\s+(?:user|localgroup)\b|\bwmic\b)/i;
const PHP_RE =
  /(?:<\?php\b|php:\/\/|\$_(?:GET|POST|REQUEST|SERVER|COOKIE|FILES)\b|\ballow_url_include\b|\bbase64_decode\s*\()/i;
const WORDPRESS_RE = /\/(?:wp-admin|wp-login\.php|wp-content|wp-includes|wp-config\.php|xmlrpc\.php)/i;
const ADMIN_PATH_RE =
  /^\/(?:admin|administrator|phpmyadmin|pma|manager\/html|jmx-console|cgi-bin|console|adminer\.php|wp-admin)\b/i;
const EXPLOITABLE_PATH_RE =
  /\/(?:web-inf|meta-inf|\.git\b|\.svn\b|\.env\b|\.aws\/credentials|server-status|actuator\/env|struts|jenkins\/script)/i;
const LOG4J_RE = /\$\{(?:jndi:|[^}]{0,20}(?:lower|upper|env|sys|date|ctx):)/i;
// "rO0AB" is the base64 of the serialization header; \xac\xed\x00\x05 is that
// same header raw, and "aced0005" its hex form.
const JAVA_SERIAL_RE = /(?:rO0AB|\xac\xed\x00\x05|aced0005)/;
const HTTP_LIBRARY_UA_RE =
  /\b(?:curl|wget|python-requests|python-urllib|go-http-client|java|okhttp|libwww-perl|axios|node-fetch|httpclient|guzzle|restsharp|postmanruntime|scrapy|aiohttp)\b/i;
const BROWSER_UA_RE = /\b(?:applewebkit|gecko|trident|khtml|presto|chrome|firefox|safari|edg|opr)\b/i;
const LOCALHOST_HOST_RE = /^(?:localhost|127\.0\.0\.1|\[?::1\]?)(?::\d+)?$/i;

/** WAF's size limits are byte counts, not character counts. */
function byteLen(s: string): number {
  return Buffer.byteLength(s, "utf8");
}

const COMMON_RULE_SET: SubRule[] = [
  { name: "NoUserAgent_HEADER", test: (r) => uaOf(r) === "" },
  {
    name: "UserAgent_BadBots_HEADER",
    test: (r) => classifyUa(uaOf(r))?.category === CATEGORY_SCANNER,
  },
  { name: "SizeRestrictions_URIPATH", test: (r) => byteLen(r.path) > 1024 },
  { name: "SizeRestrictions_QUERYSTRING", test: (r) => byteLen(r.query) > 2048 },
  { name: "SizeRestrictions_BODY", test: (r) => byteLen(r.body) > 8192 },
  {
    name: "SizeRestrictions_Cookie_HEADER",
    test: (r) => byteLen(r.headers.get("cookie") ?? "") > 10240,
  },
  { name: "EC2MetaDataSSRF_BODY", test: (r) => METADATA_RE.test(r.body) },
  {
    name: "EC2MetaDataSSRF_URIPATH_QUERYARGUMENTS",
    test: (r) => METADATA_RE.test(r.path) || anyMatch(argValues(r), METADATA_RE),
  },
  {
    name: "GenericLFI_URIPATH_QUERYARGUMENTS_BODY",
    test: (r) =>
      TRAVERSAL_RE.test(r.path) || anyMatch(argValues(r), TRAVERSAL_RE) || TRAVERSAL_RE.test(r.body),
  },
  {
    name: "GenericRFI_QUERYARGUMENTS_BODY",
    test: (r) => anyMatch(argValues(r), RFI_RE) || RFI_RE.test(r.body),
  },
  {
    name: "RestrictedExtensions_URIPATH_QUERYARGUMENTS",
    test: (r) => RESTRICTED_EXT_RE.test(r.path) || anyMatch(argValues(r), RESTRICTED_EXT_RE),
  },
  {
    name: "CrossSiteScripting_BODY_QUERYARGUMENTS_URIPATH_COOKIE",
    test: (r) => injectionSurfaces(r).some((v) => looksLikeXss(v, SENSITIVITY_HIGH)),
  },
];

const KNOWN_BAD_INPUTS: SubRule[] = [
  {
    name: "Log4JRCE_HEADER_QUERYSTRING_BODY_URIPATH",
    test: (r) => anyMatch(injectionSurfaces(r), LOG4J_RE),
  },
  {
    name: "JavaDeserializationRCE_HEADER_QUERYSTRING_BODY_URIPATH",
    test: (r) => anyMatch(injectionSurfaces(r), JAVA_SERIAL_RE),
  },
  {
    name: "Host_localhost_HEADER",
    test: (r) => LOCALHOST_HOST_RE.test(r.headers.get("host") ?? ""),
  },
  { name: "PROPFIND_METHOD", test: (r) => r.method === "PROPFIND" },
  { name: "ExploitablePaths_URIPATH", test: (r) => EXPLOITABLE_PATH_RE.test(r.path) },
];

const SQLI_RULE_SET: SubRule[] = [
  {
    name: "SQLi_QUERYARGUMENTS",
    test: (r) => argValues(r).some((v) => looksLikeSqli(v, SENSITIVITY_HIGH)),
  },
  { name: "SQLi_BODY", test: (r) => looksLikeSqli(r.body, SENSITIVITY_HIGH) },
  {
    name: "SQLi_COOKIE",
    test: (r) => cookieValues(r).some((v) => looksLikeSqli(v, SENSITIVITY_HIGH)),
  },
  { name: "SQLi_URIPATH", test: (r) => looksLikeSqli(r.path, SENSITIVITY_HIGH) },
];

const LINUX_RULE_SET: SubRule[] = [
  {
    name: "LFI_URIPATH_QUERYARGUMENTS_BODY",
    test: (r) => anyMatch([r.path, ...argValues(r), r.body], LFI_FILE_RE),
  },
  {
    name: "ShellShock_HEADER",
    test: (r) => anyMatch([...r.headers.values()], SHELLSHOCK_RE),
  },
];

const UNIX_RULE_SET: SubRule[] = [
  ...LINUX_RULE_SET,
  {
    name: "UNIXShellCommandsVariables",
    test: (r) => anyMatch(injectionSurfaces(r), SHELL_RE),
  },
];

const WINDOWS_RULE_SET: SubRule[] = [
  { name: "WindowsShellCommands", test: (r) => anyMatch(injectionSurfaces(r), WINDOWS_RE) },
];

const PHP_RULE_SET: SubRule[] = [
  { name: "PHPHighRiskMethodsVariables", test: (r) => anyMatch(injectionSurfaces(r), PHP_RE) },
];

const WORDPRESS_RULE_SET: SubRule[] = [
  { name: "WordPressExploitableCommands", test: (r) => WORDPRESS_RE.test(r.path) },
];

const ADMIN_PROTECTION: SubRule[] = [
  { name: "AdminProtection_URIPATH", test: (r) => ADMIN_PATH_RE.test(r.path) },
];

const BOT_CONTROL: SubRule[] = [
  { name: "CategoryHttpLibrary", test: (r) => HTTP_LIBRARY_UA_RE.test(uaOf(r)) },
  {
    name: "SignalNonBrowserUserAgent",
    test: (r) => {
      const ua = uaOf(r);
      return ua !== "" && !BROWSER_UA_RE.test(ua) && !HTTP_LIBRARY_UA_RE.test(ua);
    },
  },
  {
    name: "CategoryScrapingFramework",
    test: (r) => {
      const c = classifyUa(uaOf(r));
      return c !== null && (c.category === CATEGORY_SCANNER || c.category === CATEGORY_RECON);
    },
  },
];

interface GroupSpec {
  slug: string;
  rules: SubRule[];
}

const MANAGED_GROUPS: Record<string, GroupSpec> = {
  awsmanagedrulescommonruleset: { slug: "core-rule-set", rules: COMMON_RULE_SET },
  awsmanagedrulesknownbadinputsruleset: { slug: "known-bad-inputs", rules: KNOWN_BAD_INPUTS },
  awsmanagedrulessqliruleset: { slug: "sql-database", rules: SQLI_RULE_SET },
  awsmanagedruleslinuxruleset: { slug: "linux-os", rules: LINUX_RULE_SET },
  awsmanagedrulesunixruleset: { slug: "posix-os", rules: UNIX_RULE_SET },
  awsmanagedruleswindowsruleset: { slug: "windows-os", rules: WINDOWS_RULE_SET },
  awsmanagedrulesphpruleset: { slug: "php-app", rules: PHP_RULE_SET },
  awsmanagedruleswordpressruleset: { slug: "wordpress-app", rules: WORDPRESS_RULE_SET },
  awsmanagedrulesadminprotectionruleset: { slug: "admin-protection", rules: ADMIN_PROTECTION },
  awsmanagedrulesbotcontrolruleset: { slug: "bot-control", rules: BOT_CONTROL },
};

/**
 * Groups whose decision lives in AWS-side data. Private space is still a
 * definite no-match; anything routable is honestly UNKNOWN.
 */
const REPUTATION_GROUPS: Record<string, string> = {
  awsmanagedrulesamazonipreputationlist:
    "IP 평판 목록은 AWS 내부 데이터 — 공인 IP는 로컬에서 판정할 수 없음(사설 IP만 미매칭으로 확정)",
  awsmanagedrulesanonymousiplist:
    "익명 프록시/VPN 목록은 AWS 내부 데이터 — 공인 IP는 로컬에서 판정할 수 없음(사설 IP만 미매칭으로 확정)",
};

/** Groups that need request state the sandbox does not model at all. */
const STATEFUL_GROUPS: Record<string, string> = {
  awsmanagedrulesatpruleset:
    "ATP 규칙 그룹은 로그인 시도 이력·자격증명 유출 DB에 의존 — 단일 합성 요청으로 판정 불가",
  awsmanagedrulesacfpruleset:
    "ACFP 규칙 그룹은 계정 생성 흐름 상태에 의존 — 단일 합성 요청으로 판정 불가",
};

export function evaluateManagedGroup(
  vendorName: string,
  name: string,
  req: NormalizedRequest,
  excluded: Set<string>,
): ManagedVerdict {
  if (vendorName.toLowerCase() !== "aws") {
    return {
      matched: VERDICT_UNKNOWN,
      rules: [],
      labels: [],
      note: `${vendorName} 마켓플레이스 규칙 그룹은 내용이 공개돼 있지 않아 로컬 판정 불가`,
    };
  }

  const key = name.toLowerCase();

  const stateful = STATEFUL_GROUPS[key];
  if (stateful) return { matched: VERDICT_UNKNOWN, rules: [], labels: [], note: stateful };

  const reputation = REPUTATION_GROUPS[key];
  if (reputation) {
    if (isPrivateIp(req.ip)) return { matched: VERDICT_FALSE, rules: [], labels: [], note: "" };
    return { matched: VERDICT_UNKNOWN, rules: [], labels: [], note: reputation };
  }

  const group = MANAGED_GROUPS[key];
  if (!group) {
    return {
      matched: VERDICT_UNKNOWN,
      rules: [],
      labels: [],
      note: `관리형 규칙 그룹 "${name}"의 근사 정의가 없음 — 로컬 판정 불가`,
    };
  }

  const verdict: ManagedVerdict = { matched: VERDICT_FALSE, rules: [], labels: [], note: "" };
  for (const r of group.rules) {
    if (excluded.has(r.name)) continue;
    if (r.test(req)) {
      verdict.matched = VERDICT_TRUE;
      verdict.rules.push(r.name);
      verdict.labels.push(`awswaf:managed:aws:${group.slug}:${r.name}`);
    }
  }
  return verdict;
}
