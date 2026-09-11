package keys_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/andreswebs/jwt-authorizer-lambda/internal/keys"
)

// fakeSSM serves parameters from a map; names absent from it come back in
// InvalidParameters, which is how the real GetParameters reports them.
type fakeSSM struct {
	params map[string]string
	err    error
	// lastInput records the request, so tests can assert on decryption.
	lastInput *ssm.GetParametersInput
}

func (f *fakeSSM) GetParameters(_ context.Context, in *ssm.GetParametersInput, _ ...func(*ssm.Options)) (*ssm.GetParametersOutput, error) {
	f.lastInput = in
	if f.err != nil {
		return nil, f.err
	}
	out := &ssm.GetParametersOutput{}
	for _, name := range in.Names {
		if v, ok := f.params[name]; ok {
			out.Parameters = append(out.Parameters, ssmtypes.Parameter{
				Name:  aws.String(name),
				Value: aws.String(v),
			})
			continue
		}
		out.InvalidParameters = append(out.InvalidParameters, name)
	}
	return out, nil
}

func TestSSMFetcherReturnsKeysInConfiguredOrder(t *testing.T) {
	t.Parallel()

	client := &fakeSSM{params: map[string]string{
		"/app/key-primary":   "primary-value",
		"/app/key-secondary": "secondary-value",
	}}
	// Deliberately not the order the map iterates in.
	f := keys.NewSSMFetcher(client, []string{"/app/key-primary", "/app/key-secondary"})

	got, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(Fetch()) = %d, want 2", len(got))
	}
	if string(got[0]) != "primary-value" {
		t.Errorf("first key = %q, want primary-value; primary must be tried first", got[0])
	}
	if string(got[1]) != "secondary-value" {
		t.Errorf("second key = %q, want secondary-value", got[1])
	}
	if client.lastInput == nil || client.lastInput.WithDecryption == nil || !*client.lastInput.WithDecryption {
		t.Error("WithDecryption not set; a SecureString key would come back encrypted")
	}
}

func TestSSMFetcherToleratesAbsentSecondary(t *testing.T) {
	t.Parallel()

	client := &fakeSSM{params: map[string]string{"/app/key-primary": "primary-value"}}
	f := keys.NewSSMFetcher(client, []string{"/app/key-primary", "/app/key-secondary"})

	got, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v; an unused rotation slot must not break verification", err)
	}
	if len(got) != 1 || string(got[0]) != "primary-value" {
		t.Errorf("Fetch() = %q, want [primary-value]", got)
	}
}

func TestSSMFetcherSkipsEmptyValues(t *testing.T) {
	t.Parallel()

	client := &fakeSSM{params: map[string]string{
		"/app/key-primary":   "primary-value",
		"/app/key-secondary": "",
	}}
	f := keys.NewSSMFetcher(client, []string{"/app/key-primary", "/app/key-secondary"})

	got, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("len(Fetch()) = %d, want 1; an empty parameter is not a usable key", len(got))
	}
}

func TestSSMFetcherErrorsWhenNoKeyResolves(t *testing.T) {
	t.Parallel()

	tests := map[string]*fakeSSM{
		"all absent": {params: map[string]string{}},
		"all empty":  {params: map[string]string{"/app/key-primary": ""}},
		"api error":  {err: errors.New("throttled")},
	}

	for name, client := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := keys.NewSSMFetcher(client, []string{"/app/key-primary"})
			if _, err := f.Fetch(context.Background()); err == nil {
				t.Error("Fetch() error = nil, want non-nil; no key must fail closed")
			}
		})
	}
}

func TestSSMValueFetcherReturnsParameterValue(t *testing.T) {
	t.Parallel()

	client := &fakeSSM{params: map[string]string{"/app/issuer": "org_123"}}
	f := keys.NewSSMValueFetcher(client, "/app/issuer")

	got, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if got != "org_123" {
		t.Errorf("Fetch() = %q, want org_123", got)
	}
	if client.lastInput == nil || client.lastInput.WithDecryption == nil || !*client.lastInput.WithDecryption {
		t.Error("WithDecryption not set")
	}
}

func TestSSMValueFetcherRequiresANonEmptyValue(t *testing.T) {
	t.Parallel()

	tests := map[string]*fakeSSM{
		"parameter absent": {params: map[string]string{}},
		"value empty":      {params: map[string]string{"/app/issuer": ""}},
		"api error":        {err: errors.New("throttled")},
	}

	for name, client := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := keys.NewSSMValueFetcher(client, "/app/issuer")
			// An empty issuer would disable the issuer check entirely. Having
			// asked for the check, silently dropping it is the wrong failure.
			if _, err := f.Fetch(context.Background()); err == nil {
				t.Error("Fetch() error = nil, want non-nil")
			}
		})
	}
}
