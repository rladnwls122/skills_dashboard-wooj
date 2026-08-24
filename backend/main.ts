// Serves the dashboard's data API.
//
// Configuration comes from a .env file beside the project, then the process
// environment (which wins over the file), then the settings table in SQLite
// (which wins over both, per request).

import { createServer } from "./api/api.ts";
import { loadServer, Settings } from "./config/config.ts";
import { loadDotenv } from "./config/dotenv.ts";
import { LiveProvider } from "./live/live.ts";
import { Service } from "./service/service.ts";
import { Store } from "./store/store.ts";

// Before loadServer(), which reads the environment this populates.
const dotenv = loadDotenv();
if (dotenv.path) {
  const extra = dotenv.skipped.length > 0 ? `, ${dotenv.skipped.length}개는 환경변수가 우선` : "";
  console.log(`env ${dotenv.path} — ${dotenv.applied.length}개 적용${extra}`);
}

const cfg = loadServer();

let store: Store;
try {
  store = Store.open(cfg.dbPath);
} catch (e) {
  console.error(`sqlite ${cfg.dbPath}: ${(e as Error).message}`);
  process.exit(1);
}

const settings = new Settings(store);
const provider = new LiveProvider(settings, store);
const svc = new Service(store, settings, provider);
const server = createServer(svc, cfg);

// First start should not require a trip to the 설정 screen: import the local
// `aws` CLI session once, in the background so an SSO/assume-role resolution
// never delays the listen socket.
void provider.bootstrapCredentials();

// Shut down on the first signal so a restart during an exercise does not leave
// the port held.
let closing = false;
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    if (closing) return;
    closing = true;
    server.close(() => {
      store.close();
      process.exit(0);
    });
    // A hung keep-alive connection must not hold the port past the restart.
    setTimeout(() => process.exit(0), 5_000).unref();
  });
}

const [host, portText] = splitAddr(cfg.addr);

// Without a listener, a failed bind is an unhandled 'error' event — Node prints
// a stack trace and concurrently takes the frontend down with it. During an
// exercise the operator needs the one sentence that says what to do.
server.on("error", (e: NodeJS.ErrnoException) => {
  if (e.code === "EADDRINUSE") {
    console.error(
      `${cfg.addr} 는 이미 사용 중입니다 — 이전 백엔드가 아직 살아 있거나 다른 인스턴스가 떠 있습니다. ` +
        `그 프로세스를 종료하거나 다른 포트로 실행하세요 (예: pnpm dev -p 3110).`,
    );
  } else if (e.code === "EACCES") {
    console.error(`${cfg.addr} 에 바인드할 권한이 없습니다 — 1024 미만 포트인지 확인하세요.`);
  } else {
    console.error(`백엔드 기동 실패 (${cfg.addr}): ${e.message}`);
  }
  store.close();
  process.exit(1);
});

server.listen(Number(portText), host, () => {
  console.log(`listening on ${cfg.addr} (db ${cfg.dbPath}, cors ${cfg.allowedOrigins})`);
});

/** "127.0.0.1:8787" — the port is whatever follows the last colon. */
function splitAddr(addr: string): [string, string] {
  const i = addr.lastIndexOf(":");
  if (i < 0) return ["127.0.0.1", addr];
  return [addr.slice(0, i) || "127.0.0.1", addr.slice(i + 1)];
}
