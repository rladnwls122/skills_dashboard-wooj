import "server-only";

// The one thing on this dashboard that asks something other than AWS.
//
// Every other number here comes from CloudWatch or Logs Insights, both of
// which lag by minutes and, when a panel comes back empty, cannot distinguish
// "no traffic" from "nothing published yet". "Is the service answering right
// now" is not a question that data can answer, so this asks the service.
//
// Deliberately small: one GET, one status code, one elapsed time, run only
// when someone presses the button. Nothing is stored — a probe that kept
// history would be a monitoring system, and this is a button.

import type { ProbeResult } from "@/lib/types";

const TIMEOUT_MS = 10_000;

// Long enough to tell "slow" from "gone", short enough that the button comes
// back while the operator is still looking at it.
export function probeTimeoutMs(): number {
  return TIMEOUT_MS;
}

// Only what a browser would follow. A dashboard that will GET file:// or
// gopher:// on request is a file reader with a URL bar.
export function parseTarget(raw: string): URL {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error("점검할 주소가 비어 있습니다");
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  const url = new URL(withScheme);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`http/https 주소만 점검합니다 (받은 값: ${url.protocol})`);
  }
  return url;
}

export function expectLabel(expectStatus: number | null): string {
  return expectStatus && expectStatus > 0 ? `${expectStatus} 응답만` : "2xx 응답";
}

function matches(status: number, expectStatus: number | null): boolean {
  if (expectStatus && expectStatus > 0) return status === expectStatus;
  return status >= 200 && status < 300;
}

// A probe that failed is still a completed probe: it comes back as a result
// with ok=false, not as a thrown error. The dashboard failing and the target
// failing are different facts, and collapsing them makes a dashboard bug look
// like an outage.
export async function probe(rawUrl: string, expectStatus: number | null): Promise<ProbeResult> {
  const url = parseTarget(rawUrl);
  const at = new Date().toISOString();
  const base: ProbeResult = {
    url: url.toString(),
    ok: false,
    status: null,
    elapsedMs: 0,
    at,
    error: null,
    expect: expectLabel(expectStatus),
    finalUrl: null,
  };

  const started = Date.now();
  try {
    const res = await fetch(url, {
      // Named on purpose: whoever reads the target's access log should be able
      // to tell this request apart from the traffic it stands in for — and the
      // WAF panels on this same dashboard will show it.
      headers: { "user-agent": "skills-dashboard/traffic-check" },
      redirect: "follow",
      cache: "no-store",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const elapsedMs = Date.now() - started;
    // Drained, never shown. This reports whether the service answered; a
    // response body on screen is a response body in a screenshot.
    await res.arrayBuffer().catch(() => undefined);
    return {
      ...base,
      elapsedMs,
      status: res.status,
      ok: matches(res.status, expectStatus),
      finalUrl: res.url && res.url !== url.toString() ? res.url : null,
    };
  } catch (e) {
    return { ...base, elapsedMs: Date.now() - started, error: describe(e) };
  }
}

// Node's fetch reports every transport failure as "fetch failed" and hides the
// reason — ECONNREFUSED, ENOTFOUND, a TLS error — one level down in `cause`.
// The bare message is unactionable: "refused" and "no such host" are different
// problems with different fixes.
function describe(e: unknown): string {
  if (e instanceof Error && e.name === "TimeoutError") {
    return `${TIMEOUT_MS / 1000}초 안에 응답 없음 (timeout)`;
  }
  const msg = e instanceof Error ? e.message : String(e);
  const cause = e instanceof Error ? (e.cause as { code?: string; message?: string } | undefined) : undefined;
  if (!cause) return msg;
  const detail = cause.code ?? cause.message;
  return detail ? `${msg} (${detail})` : msg;
}
