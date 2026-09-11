// Command jwt-authorizer-lambda is an AWS API Gateway custom authorizer that
// accepts a request only when it carries a valid HS256-signed JWT.
//
// It is configured entirely through the environment; see the repository README
// for the variables and their defaults.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/andreswebs/jwt-authorizer-lambda/internal/authorizer"
	"github.com/andreswebs/jwt-authorizer-lambda/internal/config"
	"github.com/andreswebs/jwt-authorizer-lambda/internal/jwt"
	"github.com/andreswebs/jwt-authorizer-lambda/internal/keys"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	handler, err := build(context.Background())
	if err != nil {
		// Refusing to start is the right failure for a misconfiguration: the
		// alternative is a function that runs and rejects every caller, which
		// looks like a credential problem at the far end.
		slog.Error("startup failed", slog.Any("err", err))
		os.Exit(1)
	}

	lambda.Start(handler)
}

// build assembles the authorizer from the environment.
func build(ctx context.Context) (func(context.Context, authorizer.Event) (authorizer.Response, error), error) {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		return nil, err
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	ssmClient := ssm.NewFromConfig(awsCfg)

	keyCache := keys.NewCache[[][]byte](
		keys.NewSSMFetcher(ssmClient, cfg.SigningKeyParameters),
		cfg.KeyCacheTTL,
		nil,
	)

	// A literal issuer never changes, so it is wrapped as a fixed provider
	// rather than given a second code path. Only the parameter form needs the
	// cache, and it is deliberately the same cache the keys use.
	var issuers authorizer.IssuerProvider = keys.NewStatic(cfg.ExpectedIssuer)
	if cfg.ExpectedIssuerParameter != "" {
		issuers = keys.NewCache[string](
			keys.NewSSMValueFetcher(ssmClient, cfg.ExpectedIssuerParameter),
			cfg.KeyCacheTTL,
			nil,
		)
	}

	verifier := jwt.NewVerifier(jwt.Config{
		RequiredClaims: cfg.RequiredClaims,
		Leeway:         cfg.Leeway,
	})

	auth, err := authorizer.New(authorizer.Config{
		PrincipalID: cfg.PrincipalID,
		HeaderKey:   cfg.HeaderKey,
		TokenPrefix: cfg.TokenPrefix,
		RequestType: cfg.RequestType,
	}, verifier, keyCache, issuers)
	if err != nil {
		return nil, err
	}

	slog.Info("configured",
		slog.Int("signing_key_parameters", len(cfg.SigningKeyParameters)),
		slog.Bool("issuer_checked", cfg.ExpectedIssuer != "" || cfg.ExpectedIssuerParameter != ""),
		slog.Bool("issuer_from_parameter", cfg.ExpectedIssuerParameter != ""),
		slog.Any("required_claims", cfg.RequiredClaims),
		slog.Bool("request_type", cfg.RequestType),
		slog.String("key_cache_ttl", cfg.KeyCacheTTL.String()),
	)

	return logged(auth.Handle), nil
}

// logged records each decision. It deliberately never logs the credential or
// any part of it: access logs are retained far longer than a token's useful
// life, and a bearer token in CloudWatch is a bearer token anyone with log
// access can replay.
func logged(
	handle func(context.Context, authorizer.Event) (authorizer.Response, error),
) func(context.Context, authorizer.Event) (authorizer.Response, error) {
	return func(ctx context.Context, event authorizer.Event) (authorizer.Response, error) {
		resp, err := handle(ctx, event)

		attrs := []any{
			slog.String("type", event.Type),
			slog.String("method_arn", event.MethodArn),
		}

		switch {
		case err == nil:
			slog.Info("allowed", append(attrs, slog.String("principal", resp.PrincipalID))...)
		case errors.Is(err, authorizer.ErrUnauthorized):
			// The reason is logged but never returned. The caller learns only
			// that it was refused; the operator learns which check refused it.
			slog.Info("denied", append(attrs, slog.String("reason", authorizer.Reason(err)))...)
		default:
			slog.Error("failed", append(attrs, slog.Any("err", err))...)
		}

		return resp, err
	}
}
