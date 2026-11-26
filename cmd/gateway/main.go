package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	applyRoleSubcommand(os.Args[1:])
	cfg, err := gateway.LoadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	handler, err := gateway.NewChecked(cfg)
	if err != nil {
		log.Fatalf("gateway initialization failed: %v", err)
	}
	defer handler.Close()

	shutdownSignals := make(chan os.Signal, 1)
	signal.Notify(shutdownSignals, syscall.SIGINT, syscall.SIGTERM)

	if handler.AgentAutoTLS() {
		httpServer := &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           handler.AgentHTTPHandler(),
			ReadHeaderTimeout: 15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		httpsServer := &http.Server{
			Addr:              cfg.AgentTLSListenAddr,
			Handler:           handler,
			TLSConfig:         handler.AgentTLSConfig(),
			ReadHeaderTimeout: 15 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		shutdownDone := make(chan struct{})
		go func() {
			defer close(shutdownDone)
			<-shutdownSignals
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_ = httpServer.Shutdown(ctx)
			if err := httpsServer.Shutdown(ctx); err != nil {
				log.Printf("graceful HTTPS shutdown failed: %v", err)
			}
		}()
		httpLn, err := net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			log.Fatalf("HTTP-01 listener bind failed on %s: %v", cfg.ListenAddr, err)
		}
		httpsLn, err := net.Listen("tcp", cfg.AgentTLSListenAddr)
		if err != nil {
			_ = httpLn.Close()
			log.Fatalf("HTTPS listener bind failed on %s: %v", cfg.AgentTLSListenAddr, err)
		}
		go func() {
			log.Printf("Agent ACME HTTP-01 listener on %s", cfg.ListenAddr)
			if err := httpServer.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("HTTP-01 listener error: %v", err)
			}
		}()
		log.Printf("URL gateway listening on %s (mode=agent, auto_tls=true)", cfg.AgentTLSListenAddr)
		if err := httpsServer.ServeTLS(httpsLn, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTPS server failed: %v", err)
		}
		<-shutdownDone
		return
	}

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-shutdownSignals
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	log.Printf("URL gateway listening on %s (mode=%s)", cfg.ListenAddr, cfg.Role)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server failed: %v", err)
	}
	<-shutdownDone
}

func applyRoleSubcommand(args []string) {
	if len(args) == 0 {
		return
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case gateway.RoleStandalone, gateway.RoleController, gateway.RoleAgent:
		mode := strings.ToLower(strings.TrimSpace(args[0]))
		_ = os.Setenv("REFRACT_MODE", mode)
		fs := flag.NewFlagSet(mode, flag.ExitOnError)
		listen := fs.String("listen", "", "listen address (overrides LISTEN_ADDR)")
		tlsListen := fs.String("tls-listen", "", "HTTPS listen address when --auto-tls is enabled")
		autoTLS := fs.Bool("auto-tls", false, "enable built-in dynamic Let's Encrypt Auto-TLS")
		controller := fs.String("controller", "", "controller URL (overrides REFRACT_CONTROLLER_URL)")
		token := fs.String("token", "", "agent enroll token (overrides REFRACT_ENROLL_TOKEN)")
		state := fs.String("state", "", "agent state file path (overrides REFRACT_AGENT_STATE_PATH)")
		_ = fs.Parse(args[1:])
		if *listen != "" {
			_ = os.Setenv("LISTEN_ADDR", *listen)
		}
		if *tlsListen != "" {
			_ = os.Setenv("REFRACT_AGENT_TLS_LISTEN_ADDR", *tlsListen)
		}
		if *autoTLS {
			_ = os.Setenv("REFRACT_AGENT_AUTO_TLS", "true")
		}
		if *controller != "" {
			_ = os.Setenv("REFRACT_CONTROLLER_URL", *controller)
		}
		if *token != "" {
			_ = os.Setenv("REFRACT_ENROLL_TOKEN", *token)
		}
		if *state != "" {
			_ = os.Setenv("REFRACT_AGENT_STATE_PATH", *state)
		}
	}
}
