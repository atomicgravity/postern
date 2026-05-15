// Command broker runs the unwrapped Postern broker as a long-running HTTP
// process. The API-Gateway-fronted Lambda variant lives at cmd/broker-lambda;
// both share dep wiring via internal/brokerwire.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atomicgravity/postern/internal/brokerwire"
	"github.com/atomicgravity/postern/internal/logging"
	"github.com/atomicgravity/postern/pkg/brokerhandlers"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// shutdownGracePeriod bounds the post-signal drain. Long enough for the
// slowest /ssh/cert round-trip (KMS Sign + AVP + DynamoDB + CloudWatch).
const shutdownGracePeriod = 30 * time.Second

func main() {
	logging.Configure()
	if err := run(); err != nil {
		slog.Error("broker exited", "error", err)
		os.Exit(1)
	}
}

// run wires the broker process, starts the HTTP server, and blocks until
// SIGTERM/SIGINT triggers a bounded graceful shutdown. --addr overrides
// Listen.Addr from config / POSTERN_BROKER_ADDR.
func run() error {
	addrFlag := flag.String("addr", "", "HTTP listen address (overrides config and POSTERN_BROKER_ADDR)")
	configPath := flag.String("config", "", "broker config path")
	printConfig := flag.Bool("print-config", false, "print resolved broker config and exit")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	resolvedConfig, err := brokerhandlers.LoadResolvedConfig(brokerhandlers.LoadConfigOptions{Path: *configPath})
	if err != nil {
		return err
	}
	if *addrFlag != "" {
		resolvedConfig.Config.Listen.Addr = *addrFlag
		resolvedConfig.Sources["listen.addr"] = "--addr flag"
	}
	if *printConfig {
		return brokerhandlers.PrintResolvedConfig(os.Stdout, resolvedConfig)
	}

	awsConfig, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	deps, err := brokerwire.BuildDeps(ctx, awsConfig, resolvedConfig.Config)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              resolvedConfig.Config.Listen.Addr,
		Handler:           brokerhandlers.New(deps),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	listenErr := make(chan error, 1)
	go func() {
		slog.Info("starting broker", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
			return
		}
		listenErr <- nil
	}()

	select {
	case err := <-listenErr:
		// ListenAndServe returned before any signal — bind failure or similar.
		return err
	case <-ctx.Done():
		slog.Info("shutting down broker")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return err
	}

	if err := <-listenErr; err != nil {
		return err
	}

	return nil
}
