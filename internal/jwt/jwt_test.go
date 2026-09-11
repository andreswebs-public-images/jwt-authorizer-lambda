package jwt_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/andreswebs/jwt-authorizer-lambda/internal/jwt"
)

// mint builds a signed JWT from a raw header and claims map. Tests that need a
// malformed or hostile token build it here rather than through the verifier, so
// the verifier never participates in constructing its own input.
func mint(t *testing.T, header map[string]any, claims map[string]any, key string) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(header) + "." + enc(claims)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(signing))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signing + "." + sig
}

func hs256(t *testing.T, claims map[string]any, key string) string {
	t.Helper()
	return mint(t, map[string]any{"alg": "HS256", "typ": "JWT"}, claims, key)
}

func TestVerifyAcceptsValidToken(t *testing.T) {
	t.Parallel()

	const key = "org-api-key"
	token := hs256(t, map[string]any{"iss": "org_123"}, key)

	v := jwt.NewVerifier(jwt.Config{})

	claims, err := v.Verify(token, mat([][]byte{[]byte(key)}))
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if claims.Issuer != "org_123" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "org_123")
	}
	if strings.Contains(token, "\n") {
		t.Error("minted token must be a single line")
	}
}

func TestVerifyRejectsNonHS256Algorithms(t *testing.T) {
	t.Parallel()

	const key = "org-api-key"

	tests := map[string]string{
		"none":       "none",
		"uppercase":  "NONE",
		"asymmetric": "RS256",
		"weaker mac": "HS1",
		"empty":      "",
	}

	for name, alg := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			header := map[string]any{"alg": alg, "typ": "JWT"}
			// Signed with the real key, so only the alg check can reject it.
			token := mint(t, header, map[string]any{"iss": "org_123"}, key)

			v := jwt.NewVerifier(jwt.Config{})
			if _, err := v.Verify(token, mat([][]byte{[]byte(key)})); !errors.Is(err, jwt.ErrUnsupportedAlgorithm) {
				t.Errorf("Verify() error = %v, want ErrUnsupportedAlgorithm", err)
			}
		})
	}
}

func TestVerifyValidatesTimeClaims(t *testing.T) {
	t.Parallel()

	const key = "org-api-key"
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		claims map[string]any
		leeway time.Duration
		want   error
	}{
		{
			name:   "no exp is tolerated",
			claims: map[string]any{"iss": "org_123"},
			want:   nil,
		},
		{
			name:   "exp in the future",
			claims: map[string]any{"iss": "org_123", "exp": now.Add(time.Hour).Unix()},
			want:   nil,
		},
		{
			name:   "exp in the past",
			claims: map[string]any{"iss": "org_123", "exp": now.Add(-time.Hour).Unix()},
			want:   jwt.ErrExpired,
		},
		{
			name:   "exp just past but within leeway",
			claims: map[string]any{"iss": "org_123", "exp": now.Add(-20 * time.Second).Unix()},
			leeway: time.Minute,
			want:   nil,
		},
		{
			name:   "nbf in the future",
			claims: map[string]any{"iss": "org_123", "nbf": now.Add(time.Hour).Unix()},
			want:   jwt.ErrNotYetValid,
		},
		{
			name:   "nbf just future but within leeway",
			claims: map[string]any{"iss": "org_123", "nbf": now.Add(20 * time.Second).Unix()},
			leeway: time.Minute,
			want:   nil,
		},
		{
			name:   "nbf in the past",
			claims: map[string]any{"iss": "org_123", "nbf": now.Add(-time.Hour).Unix()},
			want:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			token := hs256(t, tc.claims, key)
			v := jwt.NewVerifier(jwt.Config{
				Leeway: tc.leeway,
				Now:    func() time.Time { return now },
			})
			_, err := v.Verify(token, mat([][]byte{[]byte(key)}))
			if !errors.Is(err, tc.want) {
				t.Errorf("Verify() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyEnforcesRequiredClaims(t *testing.T) {
	t.Parallel()

	const key = "org-api-key"
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		claims   map[string]any
		required []string
		want     error
	}{
		{
			name:     "required claim present",
			claims:   map[string]any{"iss": "org_123", "exp": now.Add(time.Hour).Unix()},
			required: []string{"exp"},
			want:     nil,
		},
		{
			name:     "required claim absent",
			claims:   map[string]any{"iss": "org_123"},
			required: []string{"exp"},
			want:     jwt.ErrMissingClaim,
		},
		{
			name:     "nothing required, nothing present",
			claims:   map[string]any{"iss": "org_123"},
			required: nil,
			want:     nil,
		},
		{
			name:     "one of several missing",
			claims:   map[string]any{"iss": "org_123", "exp": now.Add(time.Hour).Unix()},
			required: []string{"exp", "jti"},
			want:     jwt.ErrMissingClaim,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			token := hs256(t, tc.claims, key)
			v := jwt.NewVerifier(jwt.Config{
				RequiredClaims: tc.required,
				Now:            func() time.Time { return now },
			})
			if _, err := v.Verify(token, mat([][]byte{[]byte(key)})); !errors.Is(err, tc.want) {
				t.Errorf("Verify() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	t.Parallel()

	const primary = "primary-key"
	const secondary = "secondary-key"

	tests := []struct {
		name     string
		signedBy string
		keys     [][]byte
		want     error
	}{
		{
			name:     "primary key",
			signedBy: primary,
			keys:     [][]byte{[]byte(primary), []byte(secondary)},
			want:     nil,
		},
		{
			name:     "secondary key accepted during rotation",
			signedBy: secondary,
			keys:     [][]byte{[]byte(primary), []byte(secondary)},
			want:     nil,
		},
		{
			name:     "wrong key",
			signedBy: "attacker-key",
			keys:     [][]byte{[]byte(primary), []byte(secondary)},
			want:     jwt.ErrSignature,
		},
		{
			name:     "no keys configured fails closed",
			signedBy: primary,
			keys:     nil,
			want:     jwt.ErrSignature,
		},
		{
			name:     "empty key is never usable",
			signedBy: "",
			keys:     [][]byte{[]byte("")},
			want:     jwt.ErrSignature,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			token := hs256(t, map[string]any{"iss": "org_123"}, tc.signedBy)
			v := jwt.NewVerifier(jwt.Config{})
			if _, err := v.Verify(token, mat(tc.keys)); !errors.Is(err, tc.want) {
				t.Errorf("Verify() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	t.Parallel()

	const key = "org-api-key"
	token := hs256(t, map[string]any{"iss": "org_123"}, key)

	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"attacker"}`))
	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + forged + "." + parts[2]

	v := jwt.NewVerifier(jwt.Config{})
	if _, err := v.Verify(tampered, mat([][]byte{[]byte(key)})); !errors.Is(err, jwt.ErrSignature) {
		t.Errorf("Verify() error = %v, want ErrSignature", err)
	}
}

func TestVerifyRejectsMalformedTokens(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"empty":           "",
		"one segment":     "abc",
		"two segments":    "abc.def",
		"four segments":   "a.b.c.d",
		"bad base64":      "!!!.###.$$$",
		"header not json": base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".e30.c2ln",
		"claims not json": base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".c2ln",
		"only separators": "..",
		"padded base64":   "YWJj=.ZGVm=.Z2hp=",
	}

	v := jwt.NewVerifier(jwt.Config{})

	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := v.Verify(token, mat([][]byte{[]byte("k")})); err == nil {
				t.Error("Verify() error = nil, want non-nil")
			}
		})
	}
}

func TestVerifyDecodesSubjectAndAudience(t *testing.T) {
	t.Parallel()

	const key = "org-api-key"

	tests := []struct {
		name string
		aud  any
		want []string
	}{
		{name: "absent", aud: nil, want: nil},
		{name: "single string", aud: "api", want: []string{"api"}},
		{name: "array", aud: []any{"api", "admin"}, want: []string{"api", "admin"}},
		{name: "array with non-strings", aud: []any{"api", 42}, want: []string{"api"}},
		{name: "wrong type entirely", aud: 42, want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := map[string]any{"iss": "org_123", "sub": "candidate-1"}
			if tc.aud != nil {
				claims["aud"] = tc.aud
			}

			v := jwt.NewVerifier(jwt.Config{})
			got, err := v.Verify(hs256(t, claims, key), mat([][]byte{[]byte(key)}))
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if got.Subject != "candidate-1" {
				t.Errorf("Subject = %q, want candidate-1", got.Subject)
			}
			if len(got.Audience) != len(tc.want) {
				t.Fatalf("Audience = %v, want %v", got.Audience, tc.want)
			}
			for i := range tc.want {
				if got.Audience[i] != tc.want[i] {
					t.Errorf("Audience[%d] = %q, want %q", i, got.Audience[i], tc.want[i])
				}
			}
		})
	}
}

func TestVerifyRejectsNonObjectClaims(t *testing.T) {
	t.Parallel()

	const key = "org-api-key"
	// A JWT whose payload is a JSON array rather than an object: well-formed
	// base64, well-formed JSON, not a claims set.
	token := mint(t, map[string]any{"alg": "HS256", "typ": "JWT"}, nil, key)
	parts := strings.Split(token, ".")
	payload := base64.RawURLEncoding.EncodeToString([]byte(`["not","an","object"]`))
	signing := parts[0] + "." + payload
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(signing))
	resigned := signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	v := jwt.NewVerifier(jwt.Config{})
	if _, err := v.Verify(resigned, mat([][]byte{[]byte(key)})); !errors.Is(err, jwt.ErrMalformed) {
		t.Errorf("Verify() error = %v, want ErrMalformed", err)
	}
}

// mat wraps keys with the issuer these tests expect, so that a change to the
// verification-material shape touches one place rather than every call.
func mat(keys [][]byte) jwt.Material {
	return jwt.Material{Keys: keys, ExpectedIssuer: "org_123"}
}
