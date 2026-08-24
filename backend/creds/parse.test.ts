// The paste box takes whatever the operator has in hand, so the parser is the
// part that decides whether an injected key works. A session token silently
// dropped here fails as InvalidClientTokenId ten minutes later, which names
// nothing about the paste — hence the shapes below are each pinned.
//
// The parser itself is shared with the settings screen (src/lib/awscreds.ts);
// the backend imports it rather than keeping a second copy.

import assert from "node:assert/strict";
import test from "node:test";

import {
  credentialProblem,
  expiresInMs,
  isComplete,
  maskKeyId,
  maskSecret,
  parseCredentialBlob,
  parseSharedCredentialsFile,
  type ParsedCredentials,
} from "../../src/lib/awscreds.ts";

const ID = "ASIAQWERTYUIOPASDFGH";
const SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const TOKEN = "FwoGZXIvYXdzEBYaDF+examplesessiontoken//////////wEaDLong==";

const parsed = (over: Partial<ParsedCredentials>): ParsedCredentials => ({
  accessKeyId: "",
  secretAccessKey: "",
  sessionToken: "",
  expiration: "",
  ...over,
});

test("parseCredentialBlob reads every shape the operator can paste", async (t) => {
  const cases: [string, string, ParsedCredentials][] = [
    [
      // CloudShell / bash — the most common source.
      "bash export block",
      `export AWS_ACCESS_KEY_ID="${ID}"\nexport AWS_SECRET_ACCESS_KEY="${SECRET}"\nexport AWS_SESSION_TOKEN="${TOKEN}"\n`,
      parsed({ accessKeyId: ID, secretAccessKey: SECRET, sessionToken: TOKEN }),
    ],
    [
      // PowerShell — the competition shell.
      "powershell block",
      `$Env:AWS_ACCESS_KEY_ID="${ID}"\n$Env:AWS_SECRET_ACCESS_KEY="${SECRET}"\n$Env:AWS_SESSION_TOKEN="${TOKEN}"`,
      parsed({ accessKeyId: ID, secretAccessKey: SECRET, sessionToken: TOKEN }),
    ],
    [
      "cmd set block, unquoted",
      `set AWS_ACCESS_KEY_ID=${ID}\nset AWS_SECRET_ACCESS_KEY=${SECRET}\nset AWS_SESSION_TOKEN=${TOKEN}`,
      parsed({ accessKeyId: ID, secretAccessKey: SECRET, sessionToken: TOKEN }),
    ],
    [
      ".env fragment with comment and unrelated key",
      `# creds\nAWS_REGION=ap-northeast-2\nAWS_ACCESS_KEY_ID=${ID}\nAWS_SECRET_ACCESS_KEY=${SECRET}\n`,
      parsed({ accessKeyId: ID, secretAccessKey: SECRET }),
    ],
    [
      // What `aws configure export-credentials --format process` prints, on
      // one line.
      "cli process json",
      `{"Version":1,"AccessKeyId":"${ID}","SecretAccessKey":"${SECRET}","SessionToken":"${TOKEN}","Expiration":"2026-08-14T12:00:00+00:00"}`,
      parsed({
        accessKeyId: ID,
        secretAccessKey: SECRET,
        sessionToken: TOKEN,
        expiration: "2026-08-14T12:00:00+00:00",
      }),
    ],
    [
      // A key read off a screen with nothing around it.
      "bare key id",
      `  ${ID}  `,
      parsed({ accessKeyId: ID }),
    ],
    [
      // The secret must not be mistaken for the id: both names contain
      // "access key".
      "secret is not read as the key id",
      `AWS_SECRET_ACCESS_KEY=${SECRET}`,
      parsed({ secretAccessKey: SECRET }),
    ],
  ];
  for (const [name, blob, want] of cases) {
    await t.test(name, () => {
      assert.deepEqual(parseCredentialBlob(blob), want);
    });
  }
});

test("parseSharedCredentialsFile picks the named profile", () => {
  const file =
    "[default]\naws_access_key_id = AKIADEFAULTDEFAULT12\naws_secret_access_key = defaultsecret\n\n" +
    `[skills]\naws_access_key_id = ${ID}\naws_secret_access_key = ${SECRET}\naws_session_token = ${TOKEN}\n`;

  const picked = parseSharedCredentialsFile(file, "skills");
  assert.equal(picked.accessKeyId, ID);
  assert.equal(picked.sessionToken, TOKEN);
  assert.equal(parseSharedCredentialsFile(file, "default").accessKeyId, "AKIADEFAULTDEFAULT12");

  const header = `[profile skills]\naws_access_key_id = ${ID}\naws_secret_access_key = s`;
  assert.equal(parseSharedCredentialsFile(header, "skills").accessKeyId, ID);
  assert.equal(parseSharedCredentialsFile(file, "nope").accessKeyId, "");
});

test("credentialProblem names the failure the key would otherwise hide", () => {
  // A temporary key without its token is the failure that reads as "bad key".
  const asia = parsed({ accessKeyId: ID, secretAccessKey: SECRET });
  assert.equal(
    credentialProblem(asia),
    "ASIA 로 시작하는 임시 키인데 Session Token 이 없습니다 — 세 값을 함께 넣어야 합니다.",
  );
  const akia = parsed({ accessKeyId: "AKIAQWERTYUIOPASDFGH", secretAccessKey: SECRET });
  assert.equal(credentialProblem(akia), null);
  assert.equal(credentialProblem(parsed({})), "붙여넣은 값에서 키를 찾지 못했습니다.");
  assert.ok(isComplete(akia));
});

test("masks show enough to recognise, never enough to use", () => {
  assert.equal(maskKeyId(ID), "ASIA••••DFGH");
  assert.equal(maskSecret(SECRET), `•••••••• (${SECRET.length}자)`);
  assert.equal(maskKeyId(""), "");
  assert.equal(maskSecret(""), "");
});

test("expiresInMs drives the countdown and the automatic refresh", () => {
  const now = Date.UTC(2026, 7, 14, 11, 0, 0);
  assert.equal(expiresInMs("2026-08-14T12:00:00Z", now), 3_600_000);
  // Already expired reads as negative, not as absent.
  assert.equal(expiresInMs("2026-08-14T10:00:00Z", now), -3_600_000);
  assert.equal(expiresInMs("", now), null);
  assert.equal(expiresInMs("soon", now), null);
});
