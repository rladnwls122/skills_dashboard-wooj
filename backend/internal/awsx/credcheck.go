package awsx

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

import (
	"context"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// The signature was rejected — the key, the secret or the session token is
// wrong, or the temporary credentials have expired.
var authFailRe = regexp.MustCompile(`(?i)InvalidClientTokenId|SignatureDoesNotMatch|UnrecognizedClientException|InvalidAccessKeyId|ExpiredToken|TokenRefreshRequired|IncompleteSignature|AuthFailure|주입된 AWS 자격증명이 없습니다|failed to refresh cached credentials|could not load credentials|no EC2 IMDS role found`)

// The signature was accepted and the call was refused, which is a pass here.
var deniedRe = regexp.MustCompile(`(?i)AccessDenied|UnauthorizedOperation|not authorized`)

// CheckCredentials names the account the keys belong to. GetCallerIdentity is
// the cheapest call that answers it and is normally allowed even where
// everything else is denied.
func (a *AWS) CheckCredentials(ctx context.Context) types.CredentialCheck {
	region := a.Settings.Region()
	injected := a.Creds != nil && a.Creds.Injected() != nil

	client, err := a.stsClient(ctx)
	if err == nil {
		var res *sts.GetCallerIdentityOutput
		res, err = client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err == nil {
			account := aws.ToString(res.Account)
			return types.CredentialCheck{
				Status:  "OK",
				Account: account,
				Region:  region,
				Detail:  "계정 " + account + " · " + aws.ToString(res.Arn) + " 로 인증됨 (" + region + ")",
			}
		}
	}

	raw := ErrMsg(err)
	switch {
	case deniedRe.MatchString(raw):
		return types.CredentialCheck{
			Status:  "DENIED",
			Account: "",
			Region:  region,
			// Worth saying plainly: this is a pass, not a failure.
			Detail: "자격증명은 유효합니다 — 확인용 호출(sts:GetCallerIdentity)만 거부되었습니다: " + raw,
		}
	case authFailRe.MatchString(raw):
		status := "AUTH_FAIL"
		if !injected {
			status = "NO_CREDENTIALS"
		}
		return types.CredentialCheck{Status: status, Account: "", Region: region, Detail: raw}
	}
	// Anything else — a network failure, a bad region name — is reported as
	// itself rather than being folded into "bad credentials".
	return types.CredentialCheck{Status: "AUTH_FAIL", Account: "", Region: region, Detail: raw}
}
