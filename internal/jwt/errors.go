package jwt

import "errors"

// Verification failures. Callers match on these to decide how to respond; the
// values are deliberately coarse so that a rejection cannot be used to probe
// which part of a token was wrong.
var (
	// ErrMalformed means the token is not three base64url segments of JSON.
	ErrMalformed = errors.New("jwt: malformed token")
	// ErrUnsupportedAlgorithm means the header's alg is not HS256.
	ErrUnsupportedAlgorithm = errors.New("jwt: unsupported algorithm")
	// ErrSignature means no configured key produced a matching signature.
	ErrSignature = errors.New("jwt: signature mismatch")
	// ErrIssuer means the iss claim is absent or not the expected issuer.
	ErrIssuer = errors.New("jwt: unexpected issuer")
	// ErrExpired means the exp claim is in the past.
	ErrExpired = errors.New("jwt: token expired")
	// ErrNotYetValid means the nbf claim is in the future.
	ErrNotYetValid = errors.New("jwt: token not yet valid")
	// ErrMissingClaim means a claim listed as required is absent.
	ErrMissingClaim = errors.New("jwt: missing required claim")
)
