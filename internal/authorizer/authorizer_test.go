package authorizer_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/andreswebs/jwt-authorizer-lambda/internal/authorizer"
	"github.com/andreswebs/jwt-authorizer-lambda/internal/jwt"
)

const (
	testKey       = "org-api-key"
	testIssuer    = "org_123"
	testMethodArn = "arn:aws:execute-api:us-east-1:123456789012:abcdef123/default/POST/"
)

func hs256(t *testing.T, claims map[string]any, key string) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + enc(claims)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// staticKeys is a KeyProvider returning a fixed set, standing in for SSM.
type staticKeys struct {
	keys [][]byte
	err  error
}

func (s staticKeys) Get(context.Context) ([][]byte, error) { return s.keys, s.err }

// staticIssuer is an IssuerProvider standing in for a parameter lookup.
type staticIssuer struct {
	issuer string
	err    error
}

func (s staticIssuer) Get(context.Context) (string, error) { return s.issuer, s.err }

func newAuthorizer(t *testing.T, cfg authorizer.Config, provider authorizer.KeyProvider) *authorizer.Authorizer {
	t.Helper()
	a, err := authorizer.New(cfg, jwt.NewVerifier(jwt.Config{}), provider, staticIssuer{issuer: testIssuer})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return a
}

func TestHandleAllowsValidTokenEvent(t *testing.T) {
	t.Parallel()

	a := newAuthorizer(t,
		authorizer.Config{PrincipalID: "coderbyte", TokenPrefix: "Bearer"},
		staticKeys{keys: [][]byte{[]byte(testKey)}},
	)

	resp, err := a.Handle(context.Background(), authorizer.Event{
		Type:               "TOKEN",
		MethodArn:          testMethodArn,
		AuthorizationToken: "Bearer " + hs256(t, map[string]any{"iss": testIssuer}, testKey),
	})
	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}

	if resp.PrincipalID != "coderbyte" {
		t.Errorf("PrincipalID = %q, want %q", resp.PrincipalID, "coderbyte")
	}
	if len(resp.PolicyDocument.Statement) != 1 {
		t.Fatalf("Statement count = %d, want 1", len(resp.PolicyDocument.Statement))
	}
	stmt := resp.PolicyDocument.Statement[0]
	if stmt.Effect != "Allow" {
		t.Errorf("Effect = %q, want Allow", stmt.Effect)
	}
	if got := stmt.Resource; len(got) != 1 || got[0] != testMethodArn {
		t.Errorf("Resource = %v, want [%s]", got, testMethodArn)
	}
	if resp.Context["iss"] != testIssuer {
		t.Errorf("Context[iss] = %q, want %q", resp.Context["iss"], testIssuer)
	}
}

func TestHandleReadsRequestTypeHeaders(t *testing.T) {
	t.Parallel()

	token := hs256(t, map[string]any{"iss": testIssuer}, testKey)

	tests := map[string]string{
		"canonical casing": "Authorization",
		"lowercase":        "authorization",
		"screaming":        "AUTHORIZATION",
		"mixed":            "AuThOrIzAtIoN",
	}

	for name, headerName := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := newAuthorizer(t,
				authorizer.Config{TokenPrefix: "Bearer", RequestType: true},
				staticKeys{keys: [][]byte{[]byte(testKey)}},
			)
			resp, err := a.Handle(context.Background(), authorizer.Event{
				Type:      "REQUEST",
				MethodArn: testMethodArn,
				Headers:   map[string]string{headerName: "Bearer " + token},
			})
			if err != nil {
				t.Fatalf("Handle() error = %v, want nil", err)
			}
			if resp.PolicyDocument.Statement[0].Effect != "Allow" {
				t.Errorf("Effect = %q, want Allow", resp.PolicyDocument.Statement[0].Effect)
			}
		})
	}
}

func TestHandleStripsTokenPrefix(t *testing.T) {
	t.Parallel()

	token := hs256(t, map[string]any{"iss": testIssuer}, testKey)

	tests := []struct {
		name   string
		prefix string
		raw    string
	}{
		{name: "canonical", prefix: "Bearer", raw: "Bearer " + token},
		{name: "lowercase scheme", prefix: "Bearer", raw: "bearer " + token},
		{name: "uppercase scheme", prefix: "Bearer", raw: "BEARER " + token},
		{name: "extra whitespace", prefix: "Bearer", raw: "Bearer    " + token},
		{name: "no prefix configured", prefix: "", raw: token},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := newAuthorizer(t,
				authorizer.Config{TokenPrefix: tc.prefix},
				staticKeys{keys: [][]byte{[]byte(testKey)}},
			)
			if _, err := a.Handle(context.Background(), authorizer.Event{
				Type: "TOKEN", MethodArn: testMethodArn, AuthorizationToken: tc.raw,
			}); err != nil {
				t.Errorf("Handle() error = %v, want nil", err)
			}
		})
	}
}

func TestHandleRejectsBadCredentialsAs401(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"empty token":       "",
		"prefix only":       "Bearer",
		"not a jwt":         "Bearer not-a-jwt",
		"wrong key":         "Bearer " + hs256(t, map[string]any{"iss": testIssuer}, "attacker-key"),
		"wrong issuer":      "Bearer " + hs256(t, map[string]any{"iss": "somebody-else"}, testKey),
		"algorithm swapped": "Bearer " + hs256(t, map[string]any{"iss": testIssuer}, testKey) + "x",
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := newAuthorizer(t,
				authorizer.Config{TokenPrefix: "Bearer"},
				staticKeys{keys: [][]byte{[]byte(testKey)}},
			)
			_, err := a.Handle(context.Background(), authorizer.Event{
				Type: "TOKEN", MethodArn: testMethodArn, AuthorizationToken: raw,
			})
			if !errors.Is(err, authorizer.ErrUnauthorized) {
				t.Errorf("Handle() error = %v, want ErrUnauthorized", err)
			}
			if err != nil && err.Error() != "Unauthorized" {
				t.Errorf("error message = %q, want exactly %q for API Gateway to map it to 401", err.Error(), "Unauthorized")
			}
		})
	}
}

func TestHandleKeyRetrievalFailureIsNotUnauthorized(t *testing.T) {
	t.Parallel()

	a := newAuthorizer(t,
		authorizer.Config{TokenPrefix: "Bearer"},
		staticKeys{err: errors.New("ssm unavailable")},
	)

	_, err := a.Handle(context.Background(), authorizer.Event{
		Type:               "TOKEN",
		MethodArn:          testMethodArn,
		AuthorizationToken: "Bearer " + hs256(t, map[string]any{"iss": testIssuer}, testKey),
	})
	if err == nil {
		t.Fatal("Handle() error = nil, want non-nil")
	}
	if errors.Is(err, authorizer.ErrUnauthorized) {
		t.Error("infrastructure failure reported as Unauthorized; caller would see 401 and stop retrying")
	}
}

func TestNewRejectsMissingCollaborators(t *testing.T) {
	t.Parallel()

	if _, err := authorizer.New(authorizer.Config{}, nil, staticKeys{}, staticIssuer{}); err == nil {
		t.Error("New() with nil verifier error = nil, want non-nil")
	}
	if _, err := authorizer.New(authorizer.Config{}, jwt.NewVerifier(jwt.Config{}), nil, staticIssuer{}); err == nil {
		t.Error("New() with nil key provider error = nil, want non-nil")
	}
	if _, err := authorizer.New(authorizer.Config{}, jwt.NewVerifier(jwt.Config{}), staticKeys{}, nil); err == nil {
		t.Error("New() with nil issuer provider error = nil, want non-nil")
	}
}

func TestHandleIssuerRetrievalFailureIsNotUnauthorized(t *testing.T) {
	t.Parallel()

	a, err := authorizer.New(
		authorizer.Config{TokenPrefix: "Bearer"},
		jwt.NewVerifier(jwt.Config{}),
		staticKeys{keys: [][]byte{[]byte(testKey)}},
		staticIssuer{err: errors.New("parameter unavailable")},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = a.Handle(context.Background(), authorizer.Event{
		Type:               "TOKEN",
		MethodArn:          testMethodArn,
		AuthorizationToken: "Bearer " + hs256(t, map[string]any{"iss": testIssuer}, testKey),
	})
	if err == nil {
		t.Fatal("Handle() error = nil, want non-nil")
	}
	// An unreadable issuer must not silently become "no issuer check", and must
	// not be reported to the caller as a bad credential.
	if errors.Is(err, authorizer.ErrUnauthorized) {
		t.Error("issuer lookup failure reported as Unauthorized")
	}
}

func TestHandleReportsRejectionReason(t *testing.T) {
	t.Parallel()

	algNone := func() string {
		b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
		return b64(`{"alg":"none","typ":"JWT"}`) + "." + b64(`{"iss":"`+testIssuer+`"}`) + "."
	}()

	tests := []struct {
		name     string
		token    string
		required []string
		want     string
	}{
		{name: "malformed", token: "garbage", want: "malformed"},
		{name: "unsupported algorithm", token: algNone, want: "unsupported_algorithm"},
		{name: "signature", token: hs256(t, map[string]any{"iss": testIssuer}, "wrong-key"), want: "signature"},
		{name: "issuer", token: hs256(t, map[string]any{"iss": "somebody-else"}, testKey), want: "issuer"},
		{
			name:  "expired",
			token: hs256(t, map[string]any{"iss": testIssuer, "exp": time.Now().Add(-time.Hour).Unix()}, testKey),
			want:  "expired",
		},
		{
			name:  "not yet valid",
			token: hs256(t, map[string]any{"iss": testIssuer, "nbf": time.Now().Add(time.Hour).Unix()}, testKey),
			want:  "not_yet_valid",
		},
		{
			name:     "missing claim",
			token:    hs256(t, map[string]any{"iss": testIssuer}, testKey),
			required: []string{"exp"},
			want:     "missing_claim",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a, err := authorizer.New(
				authorizer.Config{TokenPrefix: "Bearer"},
				jwt.NewVerifier(jwt.Config{RequiredClaims: tc.required}),
				staticKeys{keys: [][]byte{[]byte(testKey)}},
				staticIssuer{issuer: testIssuer},
			)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			_, err = a.Handle(context.Background(), authorizer.Event{
				Type: "TOKEN", MethodArn: testMethodArn, AuthorizationToken: "Bearer " + tc.token,
			})

			// The message API Gateway sees must not change, whatever the reason.
			if err == nil || err.Error() != "Unauthorized" {
				t.Fatalf("error = %v, want exactly \"Unauthorized\"", err)
			}
			if !errors.Is(err, authorizer.ErrUnauthorized) {
				t.Errorf("errors.Is(err, ErrUnauthorized) = false")
			}
			if got := authorizer.Reason(err); got != tc.want {
				t.Errorf("Reason() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReasonOfUnrelatedErrors(t *testing.T) {
	t.Parallel()

	if got := authorizer.Reason(nil); got != "" {
		t.Errorf("Reason(nil) = %q, want empty", got)
	}
	if got := authorizer.Reason(errors.New("ssm unavailable")); got != "unknown" {
		t.Errorf("Reason(unrelated) = %q, want \"unknown\"", got)
	}
}
