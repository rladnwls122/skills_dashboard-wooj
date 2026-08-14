// Command backend serves the dashboard's data API.
//
// It replaces the Next.js server actions: same behaviour, same JSON contract,
// different process. Configuration comes from the environment and from the
// settings table in SQLite — no .env file is read here.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/api"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/live"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/service"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
)

func main() {
	cfg := config.LoadServer()

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("sqlite %s: %v", cfg.DBPath, err)
	}
	defer st.Close()

	settings := config.NewSettings(st)
	svc := service.New(st, settings, live.New(settings, st))
	app := api.New(svc, cfg)

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

	log.Printf("listening on %s (db %s, cors %s)", cfg.Addr, cfg.DBPath, cfg.AllowedOrigins)
	if err := app.Listen(cfg.Addr); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
