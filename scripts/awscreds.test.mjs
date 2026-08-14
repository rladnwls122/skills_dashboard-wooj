// The paste box takes whatever the operator has in hand, so the parser is the
// part that decides whether an injected key works. A session token silently
// dropped here fails as InvalidClientTokenId ten minutes later, which names
// nothing about the paste — hence the shapes below are each pinned.
const SRC = new URL("../src/lib/", import.meta.url).href;
const {
  parseCredentialBlob,
  parseSharedCredentialsFile,
  credentialProblem,
  isComplete,
  maskKeyId,
  maskSecret,
  expiresInMs,
} = await import(`${SRC}awscreds.ts`);

let failures = 0;
const check = (name, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures += 1;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name}` +
      (ok ? "" : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`),
  );
};

const ID = "ASIAQWERTYUIOPASDFGH";
const SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const TOKEN = "FwoGZXIvYXdzEBYaDF+examplesessiontoken//////////wEaDLong==";

// CloudShell / bash — the most common source.
const bash = parseCredentialBlob(
  `export AWS_ACCESS_KEY_ID="${ID}"\nexport AWS_SECRET_ACCESS_KEY="${SECRET}"\nexport AWS_SESSION_TOKEN="${TOKEN}"\n`,
);
check("bash export block", [bash.accessKeyId, bash.secretAccessKey, bash.sessionToken], [ID, SECRET, TOKEN]);

// PowerShell — the competition shell.
const ps = parseCredentialBlob(
  `$Env:AWS_ACCESS_KEY_ID="${ID}"\n$Env:AWS_SECRET_ACCESS_KEY="${SECRET}"\n$Env:AWS_SESSION_TOKEN="${TOKEN}"`,
);
check("powershell block", [ps.accessKeyId, ps.secretAccessKey, ps.sessionToken], [ID, SECRET, TOKEN]);

// cmd.exe, unquoted.
const cmd = parseCredentialBlob(
  `set AWS_ACCESS_KEY_ID=${ID}\nset AWS_SECRET_ACCESS_KEY=${SECRET}\nset AWS_SESSION_TOKEN=${TOKEN}`,
);
check("cmd set block", [cmd.accessKeyId, cmd.secretAccessKey, cmd.sessionToken], [ID, SECRET, TOKEN]);

// .env fragment, with a comment and an unrelated key alongside.
const env = parseCredentialBlob(
  `# creds\nAWS_REGION=ap-northeast-2\nAWS_ACCESS_KEY_ID=${ID}\nAWS_SECRET_ACCESS_KEY=${SECRET}\n`,
);
check("env fragment", [env.accessKeyId, env.secretAccessKey, env.sessionToken], [ID, SECRET, ""]);

// What `aws configure export-credentials --format process` prints, on one line.
const json = parseCredentialBlob(
  `{"Version":1,"AccessKeyId":"${ID}","SecretAccessKey":"${SECRET}","SessionToken":"${TOKEN}","Expiration":"2026-08-14T12:00:00+00:00"}`,
);
check(
  "cli process json",
  [json.accessKeyId, json.secretAccessKey, json.sessionToken, json.expiration],
  [ID, SECRET, TOKEN, "2026-08-14T12:00:00+00:00"],
);

// The secret must not be mistaken for the id: both names contain "access key".
check("secret is not read as the key id", parseCredentialBlob(`AWS_SECRET_ACCESS_KEY=${SECRET}`).accessKeyId, "");

// A key read off a screen with nothing around it.
check("bare key id", parseCredentialBlob(`  ${ID}  `).accessKeyId, ID);

// A profile section, picked out of a file that holds several.
const file = `[default]\naws_access_key_id = AKIADEFAULTDEFAULT12\naws_secret_access_key = defaultsecret\n\n[skills]\naws_access_key_id = ${ID}\naws_secret_access_key = ${SECRET}\naws_session_token = ${TOKEN}\n`;
const picked = parseSharedCredentialsFile(file, "skills");
check("named profile", [picked.accessKeyId, picked.sessionToken], [ID, TOKEN]);
check("default profile", parseSharedCredentialsFile(file, "default").accessKeyId, "AKIADEFAULTDEFAULT12");
check("[profile name] header form", parseSharedCredentialsFile(`[profile skills]\naws_access_key_id = ${ID}\naws_secret_access_key = s`, "skills").accessKeyId, ID);
check("unknown profile yields nothing", parseSharedCredentialsFile(file, "nope").accessKeyId, "");

// A temporary key without its token is the failure that reads as "bad key".
check(
  "ASIA without a session token is refused",
  credentialProblem({ accessKeyId: ID, secretAccessKey: SECRET, sessionToken: "", expiration: "" }),
  "ASIA 로 시작하는 임시 키인데 Session Token 이 없습니다 — 세 값을 함께 넣어야 합니다.",
);
check(
  "long-lived key needs no token",
  credentialProblem({ accessKeyId: "AKIAQWERTYUIOPASDFGH", secretAccessKey: SECRET, sessionToken: "", expiration: "" }),
  null,
);
check("empty paste is reported", credentialProblem({ accessKeyId: "", secretAccessKey: "", sessionToken: "", expiration: "" }), "붙여넣은 값에서 키를 찾지 못했습니다.");
check("completeness", isComplete({ accessKeyId: ID, secretAccessKey: SECRET, sessionToken: "", expiration: "" }), true);

// Masking: enough to recognise, never enough to use.
check("key id mask keeps both ends", maskKeyId(ID), "ASIA••••DFGH");
check("secret mask leaks only the length", maskSecret(SECRET), `•••••••• (${SECRET.length}자)`);
check("nothing to mask stays empty", [maskKeyId(""), maskSecret("")], ["", ""]);

// Expiry drives both the countdown and the automatic refresh.
const now = Date.parse("2026-08-14T11:00:00Z");
check("minutes left", expiresInMs("2026-08-14T12:00:00Z", now), 3600_000);
check("already expired is negative", expiresInMs("2026-08-14T10:00:00Z", now), -3600_000);
check("no expiry is null", expiresInMs("", now), null);
check("unparseable expiry is null", expiresInMs("soon", now), null);

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
