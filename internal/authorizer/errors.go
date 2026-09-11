package authorizer

import (
	"errors"

	"github.com/andreswebs/jwt-authorizer-lambda/internal/jwt"
)

// ErrUnauthorized rejects a request as unauthenticated.
//
// API Gateway maps an authorizer failure to 401 only when the error message is
// exactly "Unauthorized". Any other message produces 500, which would report an
// invalid credential as a fault on this side and encourage the caller to retry
// a request that can never succeed.
var ErrUnauthorized = errors.New("Unauthorized")

// rejection is an ErrUnauthorized that remembers why.
//
// The cause must not reach the caller: which check failed is exactly what an
// attacker would use to tune a forgery, and the message is fixed by API Gateway
// in any case. It is kept for the operator, who otherwise has only an
// undifferentiated "denied" to debug from.
type rejection struct {
	cause error
}

// Error returns the message API Gateway requires, never the cause.
func (r *rejection) Error() string { return ErrUnauthorized.Error() }

// Is reports that every rejection is an ErrUnauthorized.
func (r *rejection) Is(target error) bool { return target == ErrUnauthorized }

// Unwrap exposes the cause to errors.Is, so a caller that already knows which
// reason it cares about can ask for it directly.
func (r *rejection) Unwrap() error { return r.cause }

// reject wraps a verification failure as an unauthorized response.
func reject(cause error) error { return &rejection{cause: cause} }

// Reason returns a short, stable label for why a request was rejected, for
// logging. It returns the empty string for a nil error, and "unknown" for an
// error that is not a verification failure.
//
// Safe to log: it never reaches the caller, and it is the difference between an
// operator diagnosing a misconfigured issuer in seconds and bisecting a token
// by hand.
func Reason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, jwt.ErrMalformed):
		return "malformed"
	case errors.Is(err, jwt.ErrUnsupportedAlgorithm):
		return "unsupported_algorithm"
	case errors.Is(err, jwt.ErrSignature):
		return "signature"
	case errors.Is(err, jwt.ErrMissingClaim):
		return "missing_claim"
	case errors.Is(err, jwt.ErrIssuer):
		return "issuer"
	case errors.Is(err, jwt.ErrExpired):
		return "expired"
	case errors.Is(err, jwt.ErrNotYetValid):
		return "not_yet_valid"
	default:
		return "unknown"
	}
}
