package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/userreksai/AuditPlatform_server/internal/audit"
)

var version = "1.0.0"

func main() { os.Exit(run()) }
func run() int {
	configPath := flag.String("config", "config.yaml", "path to YAML configuration")
	showVersion := flag.Bool("version", false, "print version")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("audit-server " + version)
		return 0
	}
	c, err := audit.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}
	if *checkConfig {
		fmt.Printf("configuration valid (%d AWS accounts); secrets omitted\n", len(c.Accounts))
		return 0
	}
	store, err := audit.OpenStore(c.Database.Path)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer store.Close()
	service := audit.NewService(c, store, audit.AWSCollector{})
	service.RunScheduler()
	srv := &http.Server{Addr: c.Server.Address, Handler: audit.NewHandler(service), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 1 << 20}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		log.Printf("audit-server %s listening on %s; scheduled sync %s %s", version, c.Server.Address, c.Sync.Time, c.Sync.Timezone)
		done <- srv.ListenAndServe()
	}()
	exitCode := 0
	select {
	case <-ctx.Done():
	case err = <-done:
		if err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server failed: %v", err)
			exitCode = 1
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	service.Close()
	return exitCode
}
