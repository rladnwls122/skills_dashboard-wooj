import "server-only";

// "Do these keys work?" — asked with one call, before the panels are trusted.
//
// Injecting credentials that are subtly wrong (a truncated session token, the
// other account's key, an expired SSO session) does not produce an error on the
// settings screen; it produces six empty panels a minute later, which reads as
// an outage. So the save path makes one cheap call and reports what came back.
//
// The distinction that matters is authentication versus authorisation. The
// competition account carries explicit Deny statements, so a probe call can be
// refused while the credentials themselves are perfectly good — treating that
// as "bad keys" would send the operator off re-pasting a key that was never the
// problem. AccessDenied therefore counts as proof the signature was accepted.

import { DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { ec2Client } from "./aws";
import { ENV } from "./config";
import { injected } from "./credentials";
import { errMsg } from "./cloudwatch";
import type { CredentialCheck } from "@/lib/types";

// The signature was rejected — the key, the secret or the session token is
// wrong, or the temporary credentials have expired.
const AUTH_FAIL =
  /InvalidClientTokenId|SignatureDoesNotMatch|UnrecognizedClientException|InvalidAccessKeyId|ExpiredToken|TokenRefreshRequired|IncompleteSignature|AuthFailure|could not load credentials/i;

// The signature was accepted and the call was refused, which is a pass here.
const DENIED = /AccessDenied|UnauthorizedOperation|not authorized/i;

export async function checkCredentials(): Promise<CredentialCheck> {
  const region = ENV.region;
  try {
    // DescribeVpcs is the cheapest call that names the account back at us: the
    // owner id on any VPC in the region is the account the keys belong to,
    // which is the one thing worth confirming before a two-hour exercise.
    const res = await ec2Client().send(new DescribeVpcsCommand({ MaxResults: 5 }));
    const account = res.Vpcs?.find((v) => v.OwnerId)?.OwnerId ?? "";
    return {
      status: "OK",
      account,
      region,
      detail: account
        ? `계정 ${account} · ${region} 조회 성공`
        : `${region} 조회 성공 (이 리전에 VPC 가 없어 계정 번호는 확인 못 함)`,
    };
  } catch (e) {
    const raw = errMsg(e);
    if (DENIED.test(raw)) {
      return {
        status: "DENIED",
        account: "",
        region,
        // Worth saying plainly: this is a pass, not a failure.
        detail: `자격증명은 유효합니다 — 확인용 호출(ec2:DescribeVpcs)만 거부되었습니다: ${raw}`,
      };
    }
    if (AUTH_FAIL.test(raw)) {
      return {
        status: injected() ? "AUTH_FAIL" : "NO_CREDENTIALS",
        account: "",
        region,
        detail: raw,
      };
    }
    // Anything else — a network failure, a bad region name — is reported as
    // itself rather than being folded into "bad credentials".
    return { status: "AUTH_FAIL", account: "", region, detail: raw };
  }
}
