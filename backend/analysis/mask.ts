// Sensitive-data masking (spec §20). Applied to every log line and generated
// incident context before it leaves the server.

interface MaskRule {
  re: RegExp;
  replace: string;
}

const MASK_RULES: MaskRule[] = [
  { re: /(authorization\s*[:=]\s*)\S[^\r\n]*/gi, replace: "$1[REDACTED]" },
  { re: /(bearer\s+)[A-Za-z0-9\-._~+/]+=*/gi, replace: "$1[REDACTED]" },
  {
    re: /((?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|secret[-_]?key|x-api-key|session)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s&,;'"]+)/gi,
    replace: "$1[REDACTED]",
  },
  { re: /(cookie\s*[:=]\s*)[^\r\n]*/gi, replace: "$1[REDACTED]" },
  { re: /AKIA[0-9A-Z]{16}/g, replace: "[REDACTED_AWS_KEY]" },
  { re: /ASIA[0-9A-Z]{16}/g, replace: "[REDACTED_AWS_KEY]" },
  // JWT (three base64url segments)
  {
    re: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g,
    replace: "[REDACTED_JWT]",
  },
  // Kubernetes service-account token file mentions
  { re: /\/var\/run\/secrets\/kubernetes\.io\/serviceaccount\/token\S*/g, replace: "[REDACTED]" },
];

const PRIVATE_IP_RE =
  /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;

export function maskLine(line: string): string {
  let out = line;
  for (const r of MASK_RULES) {
    // The rules carry /g, and a global RegExp keeps lastIndex between calls;
    // replace() resets it, but only because it is called on the whole string.
    out = out.replace(r.re, r.replace);
  }
  return out;
}

export function maskLines(lines: string[]): string[] {
  return lines.map(maskLine);
}

export function maskText(text: string): string {
  return maskLine(text);
}

/**
 * The maskPrivateIp=true variant, kept separate because only one caller wants
 * it.
 */
export function maskPrivateIps(text: string): string {
  return maskLine(text).replace(PRIVATE_IP_RE, "[PRIVATE_IP]");
}
