// "Do these keys work?" — asked with one call, before the panels are trusted.
//
// Injecting credentials that are subtly wrong (a truncated session token, the
// other account's key, an expired SSO session) does not produce an error on the
// settings screen; it produces six empty panels a minute later, which reads as
// an outage. So the save path makes one cheap call and reports what came back.
//
// The distinction that matters is authentication versus authorisation. The
// competition account carries explicit Deny statements, so a probe call can be
// refused while the credentials themselves are perfectly good — treating that as
// "bad keys" would send the operator off re-pasting a key that was never the
// problem. AccessDenied therefore counts as proof the signature was accepted.

import { GetCallerIdentityCommand } from "@aws-sdk/client-sts";

import type { CredentialCheck } from "../../src/lib/types.ts";
import { errCode, errMsg, type AWS } from "./clients.ts";

// The signature was rejected — the key, the secret or the session token is
// wrong, or the temporary credentials have expired.
const AUTH_FAIL_RE =
  /InvalidClientTokenId|SignatureDoesNotMatch|UnrecognizedClientException|InvalidAccessKeyId|ExpiredToken|TokenRefreshRequired|IncompleteSignature|AuthFailure|주입된 AWS 자격증명이 없습니다|failed to refresh cached credentials|could not load credentials|no EC2 IMDS role found/i;

// The signature was accepted and the call was refused, which is a pass here.
const DENIED_RE = /AccessDenied|UnauthorizedOperation|not authorized/i;

/**
 * Names the account the keys belong to. GetCallerIdentity is the cheapest call
 * that answers it and is normally allowed even where everything else is denied.
 */
export async function checkCredentials(a: AWS): Promise<CredentialCheck> {
  const region = a.settings.region();
  const injected = a.creds?.injected() != null;

  let raw = "";
  try {
    const res = await a.stsClient().send(new GetCallerIdentityCommand({}));
    const account = res.Account ?? "";
    return {
      status: "OK",
      account,
      region,
      detail: `계정 ${account} · ${res.Arn ?? ""} 로 인증됨 (${region})`,
    };
  } catch (e) {
    // The SDK puts the AWS error code on `name`, and it is often the only place
    // the discriminating word appears.
    raw = [errCode(e), errMsg(e)].filter(Boolean).join(": ");
  }

  if (DENIED_RE.test(raw)) {
    return {
      status: "DENIED",
      account: "",
      region,
      // Worth saying plainly: this is a pass, not a failure.
      detail: "자격증명은 유효합니다 — 확인용 호출(sts:GetCallerIdentity)만 거부되었습니다: " + raw,
    };
  }
  if (AUTH_FAIL_RE.test(raw)) {
    return {
      status: injected ? "AUTH_FAIL" : "NO_CREDENTIALS",
      account: "",
      region,
      detail: raw,
    };
  }
  // Anything else — a network failure, a bad region name — is reported as itself
  // rather than being folded into "bad credentials".
  return { status: "AUTH_FAIL", account: "", region, detail: raw };
}
