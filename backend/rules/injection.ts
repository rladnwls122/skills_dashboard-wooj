// Local stand-ins for AWS's SqliMatchStatement / XssMatchStatement. AWS runs a
// libinjection-style tokenizer we cannot reproduce byte-for-byte, so these are
// signature detectors over well-known payload shapes. Every statement that uses
// them is reported as an approximation ("근사").

export const SENSITIVITY_LOW = "LOW";
export const SENSITIVITY_HIGH = "HIGH";
export type Sensitivity = typeof SENSITIVITY_LOW | typeof SENSITIVITY_HIGH;

// Shapes that are attack payloads in any context. LOW sensitivity uses these
// alone, which is what AWS's LOW level is for: fewer false positives.
const SQLI_STRONG = [
  /\bunion\b[\s\S]{0,40}\bselect\b/is,
  /\bselect\b[\s\S]{0,80}\bfrom\b/is,
  /\b(?:insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(?:table|database)|truncate\s+table|alter\s+table)\b/i,
  /(?:'|")\s*(?:or|and)\s+(?:'|")?[\w]+(?:'|")?\s*=\s*(?:'|")?[\w]+/i,
  /\b(?:or|and)\s+\d+\s*=\s*\d+\b/i,
  /;\s*(?:select|insert|update|delete|drop|shutdown|exec)\b/i,
  /\b(?:sleep|benchmark|pg_sleep)\s*\(/i,
  /\bwaitfor\s+delay\b/i,
  /\b(?:load_file|into\s+outfile|into\s+dumpfile)\b/i,
  /\b(?:information_schema|sysobjects|syscolumns|pg_catalog)\b/i,
  /\b(?:extractvalue|updatexml)\s*\(/i,
  /\bxp_cmdshell\b/i,
  /\/\*!\d{5}/,
];

// Weaker signals: real SQLi tells, but also things a legitimate parameter can
// contain. Only HIGH sensitivity looks at them, matching AWS's own trade-off.
const SQLI_LOOSE = [
  /'\s*(?:--|#)/,
  /(?:^|[\s&=])(?:--|#)\s*$/,
  /\b(?:cast|convert)\s*\(\s*\w+\s+as\b/i,
  /\bhaving\b\s+\d+\s*=\s*\d+/i,
  /\bgroup\s+by\b[\s\S]{0,40}\bhaving\b/is,
  /\border\s+by\s+\d+\s*(?:--|#|;|$)/i,
  /\bunion\b[\s\S]{0,20}\ball\b/is,
  /'\s*\|\|\s*'/,
  /\bconcat\s*\(\s*(?:0x|char\s*\()/i,
];

export function looksLikeSqli(value: string, sensitivity: Sensitivity): boolean {
  if (value === "") return false;
  if (SQLI_STRONG.some((re) => re.test(value))) return true;
  if (sensitivity !== SENSITIVITY_HIGH) return false;
  return SQLI_LOOSE.some((re) => re.test(value));
}

const XSS_STRONG = [
  /<\s*script\b/i,
  /<\s*\/\s*script\s*>/i,
  /\bjavascript\s*:/i,
  /\bvbscript\s*:/i,
  /\bon(?:error|load|click|mouseover|focus|blur|submit|toggle|animationstart|animationend|pointerover|beforeprint)\s*=/i,
  /<\s*(?:iframe|object|embed|svg|img|body|video|audio|marquee|details|form|input|link|meta|base|style|applet)\b[^>]*\bon[a-z]+\s*=/i,
  /<\s*(?:iframe|svg|img|embed|object|script)\b[^>]*\bsrc\s*=\s*["']?\s*(?:javascript|data)\s*:/i,
  /\bdocument\s*\.\s*(?:cookie|location|write|domain)\b/i,
  /\bwindow\s*\.\s*(?:location|name)\s*=/i,
  /\beval\s*\(\s*["'`]/i,
  /\b(?:setTimeout|setInterval|Function)\s*\(\s*["'`]/i,
  /<\s*svg\b[^>]*>\s*<\s*(?:script|animate|set)\b/i,
  /\balert\s*\(\s*(?:\d|["'`])/i,
];

const XSS_LOOSE = [
  /<\s*(?:iframe|object|embed|svg|applet|meta|base)\b/i,
  /&#x?0*(?:3c|60);/i,
  /%3c\s*script/i,
  /\bexpression\s*\(/i,
  /\bsrcdoc\s*=/i,
  /\bformaction\s*=/i,
  /<\s*\w+[^>]*\bstyle\s*=\s*["'][^"']*\burl\s*\(/i,
];

export function looksLikeXss(value: string, sensitivity: Sensitivity): boolean {
  if (value === "") return false;
  if (XSS_STRONG.some((re) => re.test(value))) return true;
  if (sensitivity !== SENSITIVITY_HIGH) return false;
  return XSS_LOOSE.some((re) => re.test(value));
}

export function readSensitivity(v: unknown): Sensitivity {
  return typeof v === "string" && v.toUpperCase() === "HIGH" ? SENSITIVITY_HIGH : SENSITIVITY_LOW;
}
