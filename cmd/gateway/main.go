package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/T-Matrix/Refract/internal/gateway"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "_maintenance-request" {
		if err := gateway.RunMaintenanceRequest(os.Stdin, os.Stdout); err != nil {
			log.Fatalf("maintenance request failed: %v", err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "_self-update-helper" {
		if err := gateway.RunSelfUpdateHelper(os.Args[2:]); err != nil {
			log.Fatalf("self-update failed: %v", err)
		}
		return
	}
	cfg, err := gateway.LoadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	handler, err := gateway.NewChecked(cfg)
	if err != nil {
		log.Fatalf("gateway initialization failed: %v", err)
	}
	defer handler.Close()

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	shutdownSignals := make(chan os.Signal, 1)
	signal.Notify(shutdownSignals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdownSignals
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	log.Printf("URL gateway listening on %s", cfg.ListenAddr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server failed: %v", err)
	}
}
