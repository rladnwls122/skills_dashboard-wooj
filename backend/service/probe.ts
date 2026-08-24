// The one thing on this dashboard that asks something other than AWS.
//
// Every other number here comes from CloudWatch or Logs Insights, both of which
// lag by minutes and, when a panel comes back empty, cannot distinguish "no
// traffic" from "nothing published yet". "Is the service answering right now" is
// not a question that data can answer, so this asks the service.
//
// Deliberately small: one GET, one status code, one elapsed time, run only when
// someone presses the button. Nothing is stored.
//
// On SSRF: the address has exactly one source, the 점검 tab's input field, and
// the service binds loopback on the operator's own machine. The response body is
// discarded, so a probe of a metadata endpoint yields a status code and a
// duration, not a credential. If this ever stops being a single-operator local
// tool, a target allowlist becomes required.

import type { ProbeResult } from "../../src/lib/types.ts";

const PROBE_TIMEOUT_MS = 10_000;

const SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

function parseTarget(raw: string): URL {
  let trimmed = raw.trim();
  if (trimmed === "") throw new Error("점검할 주소가 비어 있습니다");
  if (!SCHEME_RE.test(trimmed)) trimmed = "http://" + trimmed;

  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    throw new Error(`주소를 해석할 수 없습니다: ${raw}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`http/https 주소만 점검합니다 (받은 값: ${u.protocol})`);
  }
  if (u.host === "") throw new Error(`주소에 호스트가 없습니다: ${raw}`);
  return u;
}

function expectLabel(expectStatus: number | null | undefined): string {
  return expectStatus && expectStatus > 0 ? `${expectStatus} 응답만` : "2xx 응답";
}

function statusMatches(status: number, expectStatus: number | null | undefined): boolean {
  if (expectStatus && expectStatus > 0) return status === expectStatus;
  return status >= 200 && status < 300;
}

/**
 * Reports whether the target answered. A probe that failed is still a completed
 * probe: it comes back as a result with ok=false, not as an error. The dashboard
 * failing and the target failing are different facts, and collapsing them makes
 * a dashboard bug look like an outage. Only a malformed address throws.
 */
export async function probe(
  rawUrl: string,
  expectStatus: number | null | undefined,
): Promise<ProbeResult> {
  const u = parseTarget(rawUrl);
  const res: ProbeResult = {
    url: u.toString(),
    ok: false,
    at: new Date().toISOString(),
    expect: expectLabel(expectStatus),
    elapsedMs: 0,
    status: null,
    finalUrl: null,
    error: null,
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
  const started = Date.now();
  try {
    const response = await fetch(u, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        // Named on purpose: whoever reads the target's access log should be able
        // to tell this request apart from the traffic it stands in for.
        "user-agent": "skills-dashboard/traffic-check",
        "cache-control": "no-store",
      },
    });
    res.elapsedMs = Date.now() - started;
    // Drained, never shown. This reports whether the service answered; a
    // response body on screen is a response body in a screenshot.
    await response.arrayBuffer().catch(() => undefined);

    res.status = response.status;
    res.ok = statusMatches(response.status, expectStatus);
    if (response.url && response.url !== u.toString()) res.finalUrl = response.url;
  } catch (e) {
    res.elapsedMs = Date.now() - started;
    const aborted = (e as Error).name === "AbortError";
    res.error = aborted
      ? `${PROBE_TIMEOUT_MS / 1000}초 안에 응답 없음 (timeout)`
      : (e as Error).message;
  } finally {
    clearTimeout(timer);
  }
  return res;
}
