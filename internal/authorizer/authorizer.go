// Package authorizer turns an API Gateway custom authorizer invocation into an
// IAM policy, using a JWT verifier to decide.
//
// It handles both REST authorizer payloads. A TOKEN authorizer receives the
// credential in authorizationToken; a REQUEST authorizer receives the whole
// header map and the credential must be picked out of it.
package authorizer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/andreswebs/jwt-authorizer-lambda/internal/jwt"
)

// Event is the union of the two REST custom authorizer payload shapes. Only the
// fields relevant to a credential check are modelled; the shapes differ in
// which of them are populated, never in how they are named.
type Event struct {
	Type               string            `json:"type"`
	MethodArn          string            `json:"methodArn"`
	AuthorizationToken string            `json:"authorizationToken"`
	Headers            map[string]string `json:"headers"`
}

// Statement is one IAM policy statement.
type Statement struct {
	Action   []string `json:"Action"`
	Effect   string   `json:"Effect"`
	Resource []string `json:"Resource"`
}

// PolicyDocument is the IAM policy returned to API Gateway.
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Response is the authorizer's reply. Context values reach an integration's
// mapping template as $context.authorizer.<key> and must be scalars.
type Response struct {
	PrincipalID    string            `json:"principalId"`
	PolicyDocument PolicyDocument    `json:"policyDocument"`
	Context        map[string]string `json:"context,omitempty"`
}

// KeyProvider supplies the signing keys currently accepted. Returning more than
// one key is what makes key rotation non-disruptive.
type KeyProvider interface {
	Get(ctx context.Context) ([][]byte, error)
}

// IssuerProvider supplies the issuer tokens are expected to carry. It is a
// provider rather than a setting so that the value can come from a parameter
// store and be changed without a redeploy, exactly like the signing keys.
type IssuerProvider interface {
	Get(ctx context.Context) (string, error)
}

// Config configures an Authorizer.
type Config struct {
	// PrincipalID is reported as the caller's identity. Defaults to "user".
	PrincipalID string
	// HeaderKey names the header carrying the credential in a REQUEST
	// authorizer. Ignored for TOKEN. Defaults to "Authorization".
	HeaderKey string
	// TokenPrefix is stripped from the credential before verification, without
	// regard to case. Empty means the credential is the bare token.
	TokenPrefix string
	// RequestType makes the authorizer read headers rather than
	// authorizationToken, for deployment behind a REQUEST authorizer.
	RequestType bool
}

// Authorizer verifies a credential and issues a policy for it.
type Authorizer struct {
	cfg      Config
	verifier *jwt.Verifier
	keys     KeyProvider
	issuer   IssuerProvider
}

// New returns an Authorizer. It returns an error if any collaborator is nil,
// which would otherwise only fail at the first request.
func New(cfg Config, verifier *jwt.Verifier, keys KeyProvider, issuer IssuerProvider) (*Authorizer, error) {
	if verifier == nil {
		return nil, errors.New("authorizer: verifier is required")
	}
	if keys == nil {
		return nil, errors.New("authorizer: key provider is required")
	}
	if issuer == nil {
		return nil, errors.New("authorizer: issuer provider is required")
	}
	if cfg.PrincipalID == "" {
		cfg.PrincipalID = defaultPrincipalID
	}
	if cfg.HeaderKey == "" {
		cfg.HeaderKey = defaultHeaderKey
	}
	return &Authorizer{cfg: cfg, verifier: verifier, keys: keys, issuer: issuer}, nil
}

const (
	defaultPrincipalID = "user"
	defaultHeaderKey   = "Authorization"
)

// Handle verifies the event's credential and returns an Allow policy for the
// invoked method.
func (a *Authorizer) Handle(ctx context.Context, event Event) (Response, error) {
	token := a.token(event)

	// Neither of these is a credential problem. Surfacing them as failed
	// invocations gives the caller a 500 and a reason to retry, where a 401
	// would tell them their own credential was bad and invite them to stop.
	signingKeys, err := a.keys.Get(ctx)
	if err != nil {
		return Response{}, fmt.Errorf("retrieving keys: %w", err)
	}

	expectedIssuer, err := a.issuer.Get(ctx)
	if err != nil {
		return Response{}, fmt.Errorf("retrieving expected issuer: %w", err)
	}

	claims, err := a.verifier.Verify(token, jwt.Material{
		Keys:           signingKeys,
		ExpectedIssuer: expectedIssuer,
	})
	if err != nil {
		return Response{}, ErrUnauthorized
	}

	return Response{
		PrincipalID:    a.cfg.PrincipalID,
		PolicyDocument: allow(event.MethodArn),
		Context:        claimsContext(claims),
	}, nil
}

// token extracts the raw credential from either payload shape and strips the
// configured prefix.
func (a *Authorizer) token(event Event) string {
	raw := event.AuthorizationToken
	if a.cfg.RequestType {
		raw = header(event.Headers, a.cfg.HeaderKey)
	}
	return strings.TrimSpace(trimPrefixFold(raw, a.cfg.TokenPrefix))
}

// header looks up name in headers case-insensitively. API Gateway does not
// normalise header case, and HTTP field names are case-insensitive, so an exact
// map lookup would miss "authorization" sent in any other casing.
func header(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// trimPrefixFold removes prefix from s if present, ignoring case, along with
// the whitespace separating it from the token.
func trimPrefixFold(s, prefix string) string {
	if prefix == "" {
		return s
	}
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s
	}
	return strings.TrimSpace(s[len(prefix):])
}

// allow builds a policy permitting invocation of resource.
func allow(resource string) PolicyDocument {
	return PolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{{
			Action:   []string{"execute-api:Invoke"},
			Effect:   "Allow",
			Resource: []string{resource},
		}},
	}
}

// claimsContext selects the verified claims worth passing to the integration.
// Only claims this package validated are included: everything else in the token
// is caller-supplied and unverified, and must not be made to look otherwise.
func claimsContext(claims *jwt.Claims) map[string]string {
	if claims == nil {
		return nil
	}
	ctx := make(map[string]string, 2)
	if claims.Issuer != "" {
		ctx["iss"] = claims.Issuer
	}
	if claims.Subject != "" {
		ctx["sub"] = claims.Subject
	}
	if len(ctx) == 0 {
		return nil
	}
	return ctx
}
