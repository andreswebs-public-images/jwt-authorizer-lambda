package config_test

import (
	"testing"
	"time"

	"github.com/andreswebs/jwt-authorizer-lambda/internal/config"
)

// env builds a lookup function over a map, standing in for os.LookupEnv.
func env(vars map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
	}
}

func TestLoadRequiresSigningKeyParameters(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string]string{
		"absent": {},
		"empty":  {"SIGNING_KEY_PARAMETERS": ""},
		"commas": {"SIGNING_KEY_PARAMETERS": " , , "},
	}

	for name, vars := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := config.Load(env(vars)); err == nil {
				t.Error("Load() error = nil, want non-nil; without a key parameter nothing can be verified")
			}
		})
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(env(map[string]string{
		"SIGNING_KEY_PARAMETERS": "/app/key",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.PrincipalID != "user" {
		t.Errorf("PrincipalID = %q, want %q", cfg.PrincipalID, "user")
	}
	if cfg.HeaderKey != "Authorization" {
		t.Errorf("HeaderKey = %q, want %q", cfg.HeaderKey, "Authorization")
	}
	if cfg.TokenPrefix != "Bearer" {
		t.Errorf("TokenPrefix = %q, want %q", cfg.TokenPrefix, "Bearer")
	}
	if cfg.RequestType {
		t.Error("RequestType = true, want false; TOKEN is the default authorizer type")
	}
	if cfg.KeyCacheTTL != 5*time.Minute {
		t.Errorf("KeyCacheTTL = %v, want 5m", cfg.KeyCacheTTL)
	}
	if cfg.Leeway != time.Minute {
		t.Errorf("Leeway = %v, want 1m", cfg.Leeway)
	}
}

func TestLoadParsesSigningKeyParametersInOrder(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(env(map[string]string{
		// Spacing and a trailing comma are the shape a Terraform join tends to
		// produce when a rotation slot is left unset.
		"SIGNING_KEY_PARAMETERS": " /app/primary , /app/secondary ,",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	want := []string{"/app/primary", "/app/secondary"}
	if len(cfg.SigningKeyParameters) != len(want) {
		t.Fatalf("SigningKeyParameters = %v, want %v", cfg.SigningKeyParameters, want)
	}
	for i := range want {
		if cfg.SigningKeyParameters[i] != want[i] {
			t.Errorf("SigningKeyParameters[%d] = %q, want %q", i, cfg.SigningKeyParameters[i], want[i])
		}
	}
}

func TestLoadSelectsAuthorizerType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value   string
		want    bool
		wantErr bool
	}{
		{value: "token", want: false},
		{value: "TOKEN", want: false},
		{value: "request", want: true},
		{value: "REQUEST", want: true},
		{value: "nonsense", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Load(env(map[string]string{
				"SIGNING_KEY_PARAMETERS": "/app/key",
				"AUTHORIZER_TYPE":        tc.value,
			}))
			if tc.wantErr {
				if err == nil {
					t.Error("Load() error = nil, want non-nil for an unrecognised authorizer type")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.RequestType != tc.want {
				t.Errorf("RequestType = %v, want %v", cfg.RequestType, tc.want)
			}
		})
	}
}

func TestLoadRejectsUnparseableDurations(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"KEY_CACHE_TTL", "CLOCK_SKEW_LEEWAY"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := config.Load(env(map[string]string{
				"SIGNING_KEY_PARAMETERS": "/app/key",
				name:                     "five minutes",
			})); err == nil {
				t.Errorf("Load() error = nil, want non-nil for unparseable %s", name)
			}
		})
	}
}

func TestLoadReadsOptionalSettings(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(env(map[string]string{
		"SIGNING_KEY_PARAMETERS": "/app/key",
		"EXPECTED_ISSUER":        "org_123",
		"REQUIRED_CLAIMS":        "exp, iss",
		"PRINCIPAL_ID":           "coderbyte",
		"HEADER_KEY":             "X-Custom-Auth",
		"TOKEN_PREFIX":           "",
		"KEY_CACHE_TTL":          "30s",
		"CLOCK_SKEW_LEEWAY":      "10s",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ExpectedIssuer != "org_123" {
		t.Errorf("ExpectedIssuer = %q, want org_123", cfg.ExpectedIssuer)
	}
	if len(cfg.RequiredClaims) != 2 || cfg.RequiredClaims[0] != "exp" || cfg.RequiredClaims[1] != "iss" {
		t.Errorf("RequiredClaims = %v, want [exp iss]", cfg.RequiredClaims)
	}
	if cfg.PrincipalID != "coderbyte" {
		t.Errorf("PrincipalID = %q, want coderbyte", cfg.PrincipalID)
	}
	if cfg.HeaderKey != "X-Custom-Auth" {
		t.Errorf("HeaderKey = %q, want X-Custom-Auth", cfg.HeaderKey)
	}
	if cfg.TokenPrefix != "" {
		t.Errorf("TokenPrefix = %q, want empty; an explicitly empty prefix must not fall back to the default", cfg.TokenPrefix)
	}
	if cfg.KeyCacheTTL != 30*time.Second {
		t.Errorf("KeyCacheTTL = %v, want 30s", cfg.KeyCacheTTL)
	}
	if cfg.Leeway != 10*time.Second {
		t.Errorf("Leeway = %v, want 10s", cfg.Leeway)
	}
}

func TestLoadReadsExpectedIssuerParameter(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(env(map[string]string{
		"SIGNING_KEY_PARAMETERS":    "/app/key",
		"EXPECTED_ISSUER_PARAMETER": "/app/issuer",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ExpectedIssuerParameter != "/app/issuer" {
		t.Errorf("ExpectedIssuerParameter = %q, want /app/issuer", cfg.ExpectedIssuerParameter)
	}
	if cfg.ExpectedIssuer != "" {
		t.Errorf("ExpectedIssuer = %q, want empty when sourced from a parameter", cfg.ExpectedIssuer)
	}
}

func TestLoadRejectsBothIssuerSources(t *testing.T) {
	t.Parallel()

	// Silently preferring one would make the other look effective when it is
	// not, and the whole point of the check is knowing which issuer is enforced.
	if _, err := config.Load(env(map[string]string{
		"SIGNING_KEY_PARAMETERS":    "/app/key",
		"EXPECTED_ISSUER":           "org_123",
		"EXPECTED_ISSUER_PARAMETER": "/app/issuer",
	})); err == nil {
		t.Error("Load() error = nil, want non-nil when both issuer sources are set")
	}
}

func TestLoadAllowsNoIssuerSource(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(env(map[string]string{"SIGNING_KEY_PARAMETERS": "/app/key"}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ExpectedIssuer != "" || cfg.ExpectedIssuerParameter != "" {
		t.Error("expected no issuer source to be configured")
	}
}
