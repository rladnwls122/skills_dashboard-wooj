package creds

// Ported from scripts/awscreds.test.mjs. The paste box takes whatever the
// operator has in hand, so the parser is the part that decides whether an
// injected key works. A session token silently dropped here fails as
// InvalidClientTokenId ten minutes later, which names nothing about the paste —
// hence the shapes below are each pinned.

import (
	"fmt"
	"testing"
	"time"
)

const (
	testID     = "ASIAQWERTYUIOPASDFGH"
	testSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	testToken  = "FwoGZXIvYXdzEBYaDF+examplesessiontoken//////////wEaDLong=="
)

func TestParseBlobShapes(t *testing.T) {
	cases := []struct {
		name string
		blob string
		want Parsed
	}{
		{
			// CloudShell / bash — the most common source.
			"bash export block",
			"export AWS_ACCESS_KEY_ID=\"" + testID + "\"\nexport AWS_SECRET_ACCESS_KEY=\"" + testSecret + "\"\nexport AWS_SESSION_TOKEN=\"" + testToken + "\"\n",
			Parsed{AccessKeyID: testID, SecretAccessKey: testSecret, SessionToken: testToken},
		},
		{
			// PowerShell — the competition shell.
			"powershell block",
			"$Env:AWS_ACCESS_KEY_ID=\"" + testID + "\"\n$Env:AWS_SECRET_ACCESS_KEY=\"" + testSecret + "\"\n$Env:AWS_SESSION_TOKEN=\"" + testToken + "\"",
			Parsed{AccessKeyID: testID, SecretAccessKey: testSecret, SessionToken: testToken},
		},
		{
			"cmd set block, unquoted",
			"set AWS_ACCESS_KEY_ID=" + testID + "\nset AWS_SECRET_ACCESS_KEY=" + testSecret + "\nset AWS_SESSION_TOKEN=" + testToken,
			Parsed{AccessKeyID: testID, SecretAccessKey: testSecret, SessionToken: testToken},
		},
		{
			".env fragment with comment and unrelated key",
			"# creds\nAWS_REGION=ap-northeast-2\nAWS_ACCESS_KEY_ID=" + testID + "\nAWS_SECRET_ACCESS_KEY=" + testSecret + "\n",
			Parsed{AccessKeyID: testID, SecretAccessKey: testSecret},
		},
		{
			// What `aws configure export-credentials --format process` prints,
			// on one line.
			"cli process json",
			`{"Version":1,"AccessKeyId":"` + testID + `","SecretAccessKey":"` + testSecret + `","SessionToken":"` + testToken + `","Expiration":"2026-08-14T12:00:00+00:00"}`,
			Parsed{AccessKeyID: testID, SecretAccessKey: testSecret, SessionToken: testToken, Expiration: "2026-08-14T12:00:00+00:00"},
		},
		{
			// A key read off a screen with nothing around it.
			"bare key id",
			"  " + testID + "  ",
			Parsed{AccessKeyID: testID},
		},
		{
			// The secret must not be mistaken for the id: both names contain
			// "access key".
			"secret is not read as the key id",
			"AWS_SECRET_ACCESS_KEY=" + testSecret,
			Parsed{SecretAccessKey: testSecret},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseBlob(tc.blob); got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseSharedCredentialsFile(t *testing.T) {
	file := "[default]\naws_access_key_id = AKIADEFAULTDEFAULT12\naws_secret_access_key = defaultsecret\n\n" +
		"[skills]\naws_access_key_id = " + testID + "\naws_secret_access_key = " + testSecret + "\naws_session_token = " + testToken + "\n"

	picked := ParseSharedCredentialsFile(file, "skills")
	if picked.AccessKeyID != testID || picked.SessionToken != testToken {
		t.Errorf("named profile: got %+v", picked)
	}
	if got := ParseSharedCredentialsFile(file, "default").AccessKeyID; got != "AKIADEFAULTDEFAULT12" {
		t.Errorf("default profile: got %q", got)
	}
	header := "[profile skills]\naws_access_key_id = " + testID + "\naws_secret_access_key = s"
	if got := ParseSharedCredentialsFile(header, "skills").AccessKeyID; got != testID {
		t.Errorf("[profile name] header form: got %q", got)
	}
	if got := ParseSharedCredentialsFile(file, "nope").AccessKeyID; got != "" {
		t.Errorf("unknown profile should yield nothing, got %q", got)
	}
}

func TestProblem(t *testing.T) {
	// A temporary key without its token is the failure that reads as "bad key".
	asia := Parsed{AccessKeyID: testID, SecretAccessKey: testSecret}
	if got := asia.Problem(); got != "ASIA 로 시작하는 임시 키인데 Session Token 이 없습니다 — 세 값을 함께 넣어야 합니다." {
		t.Errorf("ASIA without token: got %q", got)
	}
	akia := Parsed{AccessKeyID: "AKIAQWERTYUIOPASDFGH", SecretAccessKey: testSecret}
	if got := akia.Problem(); got != "" {
		t.Errorf("long-lived key needs no token, got %q", got)
	}
	if got := (Parsed{}).Problem(); got != "붙여넣은 값에서 키를 찾지 못했습니다." {
		t.Errorf("empty paste: got %q", got)
	}
	if !akia.Complete() {
		t.Error("id+secret should be complete")
	}
}

func TestMasks(t *testing.T) {
	// Enough to recognise, never enough to use.
	if got := MaskKeyID(testID); got != "ASIA••••DFGH" {
		t.Errorf("key id mask: got %q", got)
	}
	want := fmt.Sprintf("•••••••• (%d자)", len(testSecret))
	if got := MaskSecret(testSecret); got != want {
		t.Errorf("secret mask: got %q, want %q", got, want)
	}
	if MaskKeyID("") != "" || MaskSecret("") != "" {
		t.Error("nothing to mask should stay empty")
	}
}

func TestExpiresInMs(t *testing.T) {
	// Expiry drives both the countdown and the automatic refresh.
	now := time.Date(2026, 8, 14, 11, 0, 0, 0, time.UTC).UnixMilli()
	if got := ExpiresInMs("2026-08-14T12:00:00Z", now); got == nil || *got != 3600_000 {
		t.Errorf("minutes left: got %v", got)
	}
	if got := ExpiresInMs("2026-08-14T10:00:00Z", now); got == nil || *got != -3600_000 {
		t.Errorf("already expired should be negative: got %v", got)
	}
	if got := ExpiresInMs("", now); got != nil {
		t.Errorf("no expiry should be nil: got %v", got)
	}
	if got := ExpiresInMs("soon", now); got != nil {
		t.Errorf("unparseable expiry should be nil: got %v", got)
	}
}
