// Package config loads the authorizer's settings from the environment.
//
// Loading is a pure function of a lookup callback rather than a direct read of
// os.Getenv, so that configuration errors are ordinary return values and the
// whole surface is testable without mutating process state.
package config

import (
	"fmt"
	"strings"
	"time"
)

// Environment variable names.
const (
	EnvSigningKeyParameters = "SIGNING_KEY_PARAMETERS"
	EnvExpectedIssuer       = "EXPECTED_ISSUER"
	EnvExpectedIssuerParam  = "EXPECTED_ISSUER_PARAMETER"
	EnvRequiredClaims       = "REQUIRED_CLAIMS"
	EnvPrincipalID          = "PRINCIPAL_ID"
	EnvHeaderKey            = "HEADER_KEY"
	EnvTokenPrefix          = "TOKEN_PREFIX"
	EnvAuthorizerType       = "AUTHORIZER_TYPE"
	EnvKeyCacheTTL          = "KEY_CACHE_TTL"
	EnvClockSkewLeeway      = "CLOCK_SKEW_LEEWAY"
)

// Defaults applied when a variable is unset.
const (
	DefaultPrincipalID = "user"
	DefaultHeaderKey   = "Authorization"
	DefaultTokenPrefix = "Bearer"
	DefaultKeyCacheTTL = 5 * time.Minute
	DefaultLeeway      = time.Minute
)

// Config is the authorizer's resolved configuration.
type Config struct {
	// SigningKeyParameters names the SSM parameters holding accepted signing
	// keys, in order. The first is the primary; the rest are rotation slots.
	SigningKeyParameters []string
	// ExpectedIssuer, when set, must equal each token's iss claim.
	ExpectedIssuer string
	// ExpectedIssuerParameter names an SSM parameter holding the expected
	// issuer, read at runtime instead of being fixed at deploy time. Mutually
	// exclusive with ExpectedIssuer.
	ExpectedIssuerParameter string
	// RequiredClaims names claims that must be present in every token.
	RequiredClaims []string
	// PrincipalID is reported as the caller's identity.
	PrincipalID string
	// HeaderKey names the credential-bearing header, for REQUEST authorizers.
	HeaderKey string
	// TokenPrefix is stripped from the credential before verification.
	TokenPrefix string
	// RequestType selects the REQUEST authorizer payload shape.
	RequestType bool
	// KeyCacheTTL is how long signing keys are reused between refreshes.
	KeyCacheTTL time.Duration
	// Leeway absorbs clock skew when checking exp and nbf.
	Leeway time.Duration
}

// LookupEnv reports an environment variable's value and whether it was set.
// It has the signature of os.LookupEnv.
type LookupEnv func(string) (string, bool)

// Load resolves configuration from lookup, applying defaults and validating
// what it finds.
func Load(lookup LookupEnv) (Config, error) {
	cfg := Config{
		SigningKeyParameters:    splitList(value(lookup, EnvSigningKeyParameters, "")),
		ExpectedIssuer:          strings.TrimSpace(value(lookup, EnvExpectedIssuer, "")),
		ExpectedIssuerParameter: strings.TrimSpace(value(lookup, EnvExpectedIssuerParam, "")),
		RequiredClaims:          splitList(value(lookup, EnvRequiredClaims, "")),
		PrincipalID:             value(lookup, EnvPrincipalID, DefaultPrincipalID),
		HeaderKey:               value(lookup, EnvHeaderKey, DefaultHeaderKey),
		TokenPrefix:             value(lookup, EnvTokenPrefix, DefaultTokenPrefix),
	}

	if len(cfg.SigningKeyParameters) == 0 {
		return Config{}, fmt.Errorf("%s must name at least one SSM parameter", EnvSigningKeyParameters)
	}

	// Refusing both is deliberate. Preferring one silently would leave the
	// other looking effective while a different issuer was actually enforced,
	// and which issuer is enforced is the entire value of the check.
	if cfg.ExpectedIssuer != "" && cfg.ExpectedIssuerParameter != "" {
		return Config{}, fmt.Errorf("%s and %s are mutually exclusive", EnvExpectedIssuer, EnvExpectedIssuerParam)
	}

	switch strings.ToLower(strings.TrimSpace(value(lookup, EnvAuthorizerType, "token"))) {
	case "token":
		cfg.RequestType = false
	case "request":
		cfg.RequestType = true
	case "":
		cfg.RequestType = false
	default:
		v, _ := lookup(EnvAuthorizerType)
		return Config{}, fmt.Errorf("%s must be \"token\" or \"request\", got %q", EnvAuthorizerType, v)
	}

	var err error
	if cfg.KeyCacheTTL, err = duration(lookup, EnvKeyCacheTTL, DefaultKeyCacheTTL); err != nil {
		return Config{}, err
	}
	if cfg.Leeway, err = duration(lookup, EnvClockSkewLeeway, DefaultLeeway); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// value returns the variable's value, or fallback when it is unset. A variable
// that is set but empty keeps its empty value: clearing TOKEN_PREFIX is how a
// caller asks for a bare token, and must not silently restore the default.
func value(lookup LookupEnv, name, fallback string) string {
	if v, ok := lookup(name); ok {
		return v
	}
	return fallback
}

// duration parses a variable as a Go duration, or returns fallback when unset
// or empty.
func duration(lookup LookupEnv, name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(value(lookup, name, ""))
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}

// splitList parses a comma-separated list, discarding surrounding whitespace
// and empty entries. An unused rotation slot renders as an empty entry, which
// is normal rather than an error.
func splitList(raw string) []string {
	var out []string
	for part := range strings.SplitSeq(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
