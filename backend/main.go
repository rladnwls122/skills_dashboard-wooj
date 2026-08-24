// Command backend serves the dashboard's data API.
//
// It replaces the Next.js server actions: same behaviour, same JSON contract,
// different process. Configuration comes from the environment and from the
// settings table in SQLite — no .env file is read here.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/api"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/live"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/service"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
)

// version is stamped by the release build via -ldflags "-X main.version=…".
// "dev" for a plain `go run` or a source build.
var version = "dev"

func main() {
	cfg := config.LoadServer()

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("sqlite %s: %v", cfg.DBPath, err)
	}
	defer st.Close()

	settings := config.NewSettings(st)
	provider := live.New(settings, st)
	svc := service.New(st, settings, provider)
	app := api.New(svc, cfg)

	// Serve the frontend from the binary in a release build (-tags embed);
	// a no-op in the default build, where Vite serves it. Registered after the
	// API routes so /api/* and /healthz win.
	mountWeb(app)

	// First start should not require a trip to the 설정 screen: import the
	// local `aws` CLI session once, in the background so an SSO/assume-role
	// resolution never delays the listen socket.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		provider.BootstrapCredentials(ctx)
	}()

	// Shut down on the first signal so a restart during an exercise does not
	// leave the port held.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := app.ShutdownWithContext(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()

	log.Printf("skills-dashboard %s — listening on %s (db %s, cors %s)", version, cfg.Addr, cfg.DBPath, cfg.AllowedOrigins)
	if err := app.Listen(cfg.Addr); err != nil {
		if isAddressInUse(err) {
			// The one startup failure that happens on a competition day, and
			// the one the raw error explains worst: a previous run of this same
			// binary is still holding the port, and "listen tcp 127.0.0.1:8080:
			// bind: Only one usage of each socket address ..." tells an
			// operator under time pressure nothing about what to do. Name the
			// address and both ways out.
			log.Fatalf("%s 주소를 이미 다른 프로세스가 사용 중이라 서버를 시작할 수 없습니다. "+
				"먼저 실행 중인 대시보드 백엔드를 종료하거나, ADDR 환경변수로 다른 포트를 지정해 다시 실행하세요. (원본 오류: %v)",
				cfg.Addr, err)
		}
		log.Fatalf("listen: %v", err)
	}
}

// isAddressInUse: the portable errno check first, then the message. Windows
// reports this as WSAEADDRINUSE (10048) and its Errno does not compare equal to
// syscall.EADDRINUSE, so the string test is not belt-and-braces here — on the
// machine this actually runs on it is the branch that fires.
func isAddressInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "only one usage of each socket address") ||
		strings.Contains(msg, "10048")
}
