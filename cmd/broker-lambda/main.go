// Command broker-lambda runs the unwrapped Postern broker as an API-Gateway-
// fronted Lambda. Init builds deps once so cold starts pay for OIDC discovery
// and KMS GetPublicKey only on the first invocation.
//
// Lambda runtime: provided.al2023 with the binary named "bootstrap" inside
// the zip; the Makefile broker-lambda.zip target produces that artifact.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/atomicgravity/postern/internal/brokerwire"
	"github.com/atomicgravity/postern/internal/logging"
	"github.com/atomicgravity/postern/pkg/brokerhandlers"
	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
)

func main() {
	logging.Configure()
	adapter, err := newAdapter(context.Background())
	if err != nil {
		// Init failures are fatal — no Lambda invocation context to surface
		// through, and retrying hits the same misconfiguration.
		slog.Error("broker-lambda init failed", "error", err)
		os.Exit(1)
	}
	lambda.Start(adapter.ProxyWithContext)
}

// newAdapter does the cold-start work: load config, build deps, mount the
// broker handler under an API Gateway v2 adapter.
func newAdapter(ctx context.Context) (*httpadapter.HandlerAdapterV2, error) {
	resolvedConfig, err := brokerhandlers.LoadResolvedConfig(brokerhandlers.LoadConfigOptions{})
	if err != nil {
		return nil, err
	}

	awsConfig, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	deps, err := brokerwire.BuildDeps(ctx, awsConfig, resolvedConfig.Config)
	if err != nil {
		return nil, err
	}

	return httpadapter.NewV2(brokerhandlers.New(deps)), nil
}
