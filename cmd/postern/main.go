// Command postern is the unwrapped Postern CLI. It assembles the cobra root
// from pkg/cliapp with default options, configures a JSON slog handler from
// POSTERN_LOG_LEVEL, and dispatches to the subcommand the engineer invoked.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/atomicgravity/postern/internal/logging"
	"github.com/atomicgravity/postern/pkg/cliapp"
)

func main() {
	logging.Configure()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	root := cliapp.New(cliapp.Options{})
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", root.Name(), err)
		os.Exit(1)
	}
}
