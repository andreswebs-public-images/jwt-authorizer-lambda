// Package jwt verifies HS256-signed JSON Web Tokens.
//
// It deliberately implements only HS256. An authorizer that accepts a set of
// algorithms has to decide which key to apply to which algorithm, and getting
// that wrong is the classic algorithm-confusion vulnerability. Supporting one
// algorithm removes the decision.
//
// The package has no AWS dependencies and does not know where keys come from:
// callers pass the accepted keys to Verify. That keeps key storage, caching and
// rotation policy outside the code that makes the security decision.
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// algorithmHS256 is the only algorithm this package accepts. Compared
// case-sensitively: RFC 7515 registers the name exactly as "HS256".
const algorithmHS256 = "HS256"

// Claims are the registered JWT claims this package interprets, plus the raw
// decoded payload for anything else the caller needs.
type Claims struct {
	Issuer   string
	Subject  string
	Audience []string
	// ExpiresAt and NotBefore are zero when the token omits the claim.
	ExpiresAt time.Time
	NotBefore time.Time
	Raw       map[string]any
}

// Material is the verification input that can change without a redeploy: the
// accepted signing keys, and the issuer they are expected to belong to.
//
// It is passed per call rather than held on the Verifier so that a caller
// refreshing keys or issuer from a parameter store does not have to rebuild the
// verifier, and cannot accidentally keep verifying against a stale copy.
type Material struct {
	// Keys are the signing keys to accept, most likely first.
	Keys [][]byte
	// ExpectedIssuer, when set, must equal the token's iss claim.
	ExpectedIssuer string
}

// Config is a Verifier's static policy: the rules that are fixed at deploy
// time. The zero value verifies the signature only.
type Config struct {
	// RequiredClaims names claims that must be present. Presence only; any
	// value-level check beyond that belongs to the specific claim's own rule.
	RequiredClaims []string
	// Leeway absorbs clock skew between this verifier and the token's issuer
	// when checking exp and nbf. Zero means no allowance.
	Leeway time.Duration
	// Now supplies the current time. Nil means time.Now.
	Now func() time.Time
}

// Verifier verifies tokens against a fixed policy.
type Verifier struct {
	cfg Config
}

// NewVerifier returns a Verifier applying cfg.
func NewVerifier(cfg Config) *Verifier {
	return &Verifier{cfg: cfg}
}

// Verify checks token's signature against each of m.Keys in turn and validates
// its claims. It returns the decoded claims, or an error describing the first
// check that failed.
func (v *Verifier) Verify(token string, m Material) (*Claims, error) {
	signing, headerJSON, sig, claimsJSON, err := split(token)
	if err != nil {
		return nil, err
	}

	// Checked before any signature work: a token naming a different algorithm
	// is rejected on that basis alone, so no key is ever applied under an
	// algorithm it was not chosen for.
	var header struct {
		Algorithm string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrMalformed
	}
	if header.Algorithm != algorithmHS256 {
		return nil, ErrUnsupportedAlgorithm
	}

	if err := verifySignature(signing, sig, m.Keys); err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(claimsJSON, &raw); err != nil {
		return nil, ErrMalformed
	}

	claims := &Claims{Raw: raw}
	if iss, ok := raw["iss"].(string); ok {
		claims.Issuer = iss
	}
	if sub, ok := raw["sub"].(string); ok {
		claims.Subject = sub
	}
	claims.Audience = audience(raw["aud"])
	if exp, ok := numericDate(raw["exp"]); ok {
		claims.ExpiresAt = exp
	}
	if nbf, ok := numericDate(raw["nbf"]); ok {
		claims.NotBefore = nbf
	}

	for _, name := range v.cfg.RequiredClaims {
		if _, ok := raw[name]; !ok {
			return nil, ErrMissingClaim
		}
	}

	if m.ExpectedIssuer != "" && claims.Issuer != m.ExpectedIssuer {
		return nil, ErrIssuer
	}

	now := time.Now()
	if v.cfg.Now != nil {
		now = v.cfg.Now()
	}
	// Both checks are skipped when the claim is absent. Coderbyte may omit exp
	// entirely; treating that as a rejection would drop every webhook, so
	// absence is tolerated and the claim is enforced only when supplied.
	if !claims.ExpiresAt.IsZero() && now.After(claims.ExpiresAt.Add(v.cfg.Leeway)) {
		return nil, ErrExpired
	}
	if !claims.NotBefore.IsZero() && now.Before(claims.NotBefore.Add(-v.cfg.Leeway)) {
		return nil, ErrNotYetValid
	}

	return claims, nil
}

// numericDate converts a JSON-decoded NumericDate claim to a time. JSON numbers
// decode to float64, so an integer-valued claim arrives as a float.
func numericDate(v any) (time.Time, bool) {
	secs, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(secs), 0).UTC(), true
}

// audience normalises the aud claim, which RFC 7519 allows to be either a
// single string or an array of strings.
func audience(v any) []string {
	switch aud := v.(type) {
	case string:
		return []string{aud}
	case []any:
		out := make([]string, 0, len(aud))
		for _, entry := range aud {
			if s, ok := entry.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// split separates token into its signing input and its decoded header,
// signature and claims segments.
//
// The signing input is returned as the exact bytes received rather than
// re-encoded from the decoded segments, because base64url admits
// representations that decode identically but sign differently.
func split(token string) (signing string, headerJSON, sig, claimsJSON []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", nil, nil, nil, ErrMalformed
	}

	headerJSON, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", nil, nil, nil, ErrMalformed
	}

	claimsJSON, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, nil, nil, ErrMalformed
	}

	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, nil, nil, ErrMalformed
	}

	return parts[0] + "." + parts[1], headerJSON, sig, claimsJSON, nil
}

// verifySignature reports whether sig is a valid HS256 signature over signing
// under any of keys.
//
// The comparison must stay hmac.Equal, which is constant time. Swapping it for
// == or bytes.Equal leaks, through timing, how many leading bytes of a forged
// signature were right, which is enough to recover a valid signature byte by
// byte. No test here can catch that substitution: the two are functionally
// identical and differ only in how long they take to disagree.
//
// Empty keys are skipped rather than used. An unset or cleared SSM parameter
// reads as the empty string, which HMAC would otherwise accept as a perfectly
// good key: anyone could then sign their own tokens. A missing key must fail
// closed, so a token that verifies only under the empty key is rejected.
func verifySignature(signing string, sig []byte, keys [][]byte) error {
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(signing))
		if hmac.Equal(mac.Sum(nil), sig) {
			return nil
		}
	}
	return ErrSignature
}
