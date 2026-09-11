package keys

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// ErrNoKeys means no configured parameter yielded a usable key.
var ErrNoKeys = errors.New("keys: no signing key available")

// ErrEmptyValue means a parameter that was asked for resolved to nothing.
var ErrEmptyValue = errors.New("keys: parameter is absent or empty")

// GetParametersAPI is the subset of the SSM client this package uses.
type GetParametersAPI interface {
	GetParameters(ctx context.Context, params *ssm.GetParametersInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersOutput, error)
}

// SSMFetcher reads signing keys from SSM Parameter Store.
type SSMFetcher struct {
	client GetParametersAPI
	names  []string
}

// NewSSMFetcher returns a Fetcher reading the named parameters, in order. The
// first name is the primary key; any further names are additional keys accepted
// during rotation, and are optional.
func NewSSMFetcher(client GetParametersAPI, names []string) *SSMFetcher {
	return &SSMFetcher{client: client, names: names}
}

// Fetch retrieves the configured parameters in a single call and returns their
// values in the order the names were configured.
//
// Parameters that do not exist, and parameters whose value is empty, are
// skipped rather than reported: a rotation slot that is not currently in use is
// the normal steady state. If nothing resolves, Fetch returns ErrNoKeys, so a
// wholly unconfigured function rejects callers instead of accepting them.
func (f *SSMFetcher) Fetch(ctx context.Context) ([][]byte, error) {
	if len(f.names) == 0 {
		return nil, ErrNoKeys
	}

	out, err := f.client.GetParameters(ctx, &ssm.GetParametersInput{
		Names:          f.names,
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("getting parameters: %w", err)
	}

	// GetParameters does not promise to preserve request order, and the order
	// matters: the primary key should be tried first so the common case costs
	// one comparison.
	byName := make(map[string]string, len(out.Parameters))
	for _, p := range out.Parameters {
		if p.Name == nil || p.Value == nil {
			continue
		}
		byName[*p.Name] = *p.Value
	}

	keys := make([][]byte, 0, len(f.names))
	for _, name := range f.names {
		if value := byName[name]; value != "" {
			keys = append(keys, []byte(value))
		}
	}

	if len(keys) == 0 {
		return nil, ErrNoKeys
	}

	return keys, nil
}

// SSMValueFetcher reads a single parameter's value from SSM Parameter Store.
type SSMValueFetcher struct {
	client GetParametersAPI
	name   string
}

// NewSSMValueFetcher returns a Fetcher reading the named parameter.
func NewSSMValueFetcher(client GetParametersAPI, name string) *SSMValueFetcher {
	return &SSMValueFetcher{client: client, name: name}
}

// Fetch retrieves the parameter's value.
//
// An absent or empty parameter is an error rather than an empty string. The
// caller asked for this value; handing back a zero value would quietly turn a
// configured check into no check at all, which is the failure mode a missing
// parameter must never produce.
func (f *SSMValueFetcher) Fetch(ctx context.Context) (string, error) {
	out, err := f.client.GetParameters(ctx, &ssm.GetParametersInput{
		Names:          []string{f.name},
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("getting parameter %s: %w", f.name, err)
	}

	for _, p := range out.Parameters {
		if p.Name != nil && *p.Name == f.name && p.Value != nil && *p.Value != "" {
			return *p.Value, nil
		}
	}

	return "", fmt.Errorf("%s: %w", f.name, ErrEmptyValue)
}
