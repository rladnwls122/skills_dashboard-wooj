import "server-only";

// Sensitive-data masking (spec §20). Applied to every log line and generated
// incident context before it leaves the server.

const RULES: { re: RegExp; replace: string }[] = [
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

const PRIVATE_IP =
  /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;

export function maskLine(line: string, maskPrivateIp = false): string {
  let out = line;
  for (const rule of RULES) out = out.replace(rule.re, rule.replace);
  if (maskPrivateIp) out = out.replace(PRIVATE_IP, "[PRIVATE_IP]");
  return out;
}

export function maskLines(lines: string[], maskPrivateIp = false): string[] {
  return lines.map((l) => maskLine(l, maskPrivateIp));
}

export function maskText(text: string, maskPrivateIp = false): string {
  return maskLine(text, maskPrivateIp);
}
