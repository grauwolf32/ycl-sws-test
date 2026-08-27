package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"sws-lab/internal/grpclab"
	"sws-lab/internal/lab"

	"google.golang.org/grpc"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("SWS lab stopped unexpectedly", "error", err)
		os.Exit(1)
	}
	logger.Info("SWS lab stopped")
}

func run(logger *slog.Logger) error {
	cfg, err := lab.LoadConfig()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	application, err := lab.New(cfg, logger)
	if err != nil {
		return fmt.Errorf("initialize HTTP application: %w", err)
	}
	grpcListener, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return fmt.Errorf("listen for gRPC on %s: %w", cfg.GRPCAddr, err)
	}

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           application.Handler(),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}
	grpcServer := grpclab.NewServer(grpclab.Config{
		AppName:        cfg.AppName,
		MaxDelay:       cfg.MaxDelay,
		MaxRecvMsgSize: int(cfg.MaxBodyBytes),
		Logger:         logger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	type serverResult struct {
		name string
		err  error
	}
	errCh := make(chan serverResult, 2)
	go func() {
		serveErr := httpServer.ListenAndServe()
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		errCh <- serverResult{name: "HTTP", err: serveErr}
	}()
	go func() {
		serveErr := grpcServer.Serve(grpcListener)
		if errors.Is(serveErr, grpc.ErrServerStopped) {
			serveErr = nil
		}
		errCh <- serverResult{name: "gRPC", err: serveErr}
	}()
	logger.Info("SWS lab started",
		"http_addr", cfg.Addr,
		"grpc_addr", cfg.GRPCAddr,
		"max_body_bytes", cfg.MaxBodyBytes,
		"trust_proxy_headers", cfg.TrustProxyHeaders,
	)

	var serveErr error
	select {
	case result := <-errCh:
		if result.err != nil {
			serveErr = fmt.Errorf("%s server: %w", result.name, result.err)
		}
	case <-ctx.Done():
		logger.Info("shutdown requested")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	httpShutdownErr := make(chan error, 1)
	go func() {
		httpShutdownErr <- httpServer.Shutdown(shutdownCtx)
	}()
	grpcStopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(grpcStopped)
	}()
	select {
	case <-grpcStopped:
	case <-shutdownCtx.Done():
		grpcServer.Stop()
		<-grpcStopped
	}

	if err = <-httpShutdownErr; err != nil {
		return errors.Join(serveErr, fmt.Errorf("shutdown HTTP server: %w", err))
	}
	return serveErr
}
