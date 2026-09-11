# jwt-authorizer-lambda

AWS Lambda authorizer for API Gateway that admits a request only when it carries
a valid HS256-signed JWT.

Signing keys are read from SSM Parameter Store, and more than one key is
accepted at a time, so a key can be rotated without dropping requests.

## Configuration

One variable is required:

- `SIGNING_KEY_PARAMETERS`: comma-separated SSM parameter names holding the
  accepted signing keys, in order. The first is the primary key; any others are
  rotation slots. Parameters that are absent or empty are skipped, so an unused
  slot is normal. If none resolve, every request is rejected.

The rest are optional:

| Variable            | Default         | Meaning                                                                                         |
| ------------------- | --------------- | ----------------------------------------------------------------------------------------------- |
| `EXPECTED_ISSUER`   | unset           | When set, must equal each token's `iss` claim. Unset means the issuer is not checked.           |
| `EXPECTED_ISSUER_PARAMETER` | unset   | SSM parameter holding the expected issuer, read at runtime. Mutually exclusive with `EXPECTED_ISSUER`. |
| `REQUIRED_CLAIMS`   | unset           | Comma-separated claims that must be present, for example `exp,iss`.                             |
| `PRINCIPAL_ID`      | `user`          | Reported as the caller's identity.                                                              |
| `AUTHORIZER_TYPE`   | `token`         | `token` or `request`, matching how the authorizer is declared in API Gateway.                   |
| `HEADER_KEY`        | `Authorization` | Header carrying the credential. Used only when `AUTHORIZER_TYPE=request`.                       |
| `TOKEN_PREFIX`      | `Bearer`        | Stripped from the credential before verification, ignoring case. Set to empty for a bare token. |
| `KEY_CACHE_TTL`     | `5m`            | How long signing keys are reused between reads.                                                 |
| `CLOCK_SKEW_LEEWAY` | `1m`            | Allowance applied when checking `exp` and `nbf`.                                                |

The execution role needs `ssm:GetParameters` on every named parameter, and
`kms:Decrypt` on the key protecting them if they are `SecureString`.

### Choosing an issuer source

`EXPECTED_ISSUER` fixes the value at deploy time. If the deployment resolves it
from a parameter store itself, the value ends up in deployment state and in the
function's visible configuration, which is fine for an issuer but would not be
for a key.

`EXPECTED_ISSUER_PARAMETER` names a parameter read at runtime and refreshed on
the same schedule as the signing keys, so the value appears nowhere but the
parameter store and a change takes effect within `KEY_CACHE_TTL` rather than at
the next deploy.

Setting both is an error rather than a precedence rule: which issuer is actually
enforced is the whole value of the check, and a silent winner would leave the
other looking effective.

If the named parameter is absent or empty, every request is rejected. A
configured check that cannot resolve must not quietly become no check.

## What is checked, in order

1. The token is three base64url segments.
2. The header's `alg` is exactly `HS256`. A token naming any other algorithm,
   `none` included, is rejected before any signature work, so a key is never
   applied under an algorithm it was not chosen for.
3. HMAC-SHA256 over `<header>.<payload>`, compared in constant time against
   each configured key in turn. Empty keys are skipped rather than used: an
   unset parameter reads as the empty string, which HMAC would otherwise accept
   as a perfectly good key.
4. Every claim named in `REQUIRED_CLAIMS` is present.
5. `iss` equals the expected issuer, when one is configured.
6. `exp` and `nbf`, each only when the token carries it, within
   `CLOCK_SKEW_LEEWAY`.

A token that passes gets an `Allow` policy for the invoked method ARN, and its
verified `iss` and `sub` are returned as authorizer context, reachable from an
integration mapping template as `$context.authorizer.iss`. Only claims that were
actually validated are passed on; everything else in the token is
caller-supplied and is not made to look otherwise.

## Failure behaviour

Distinguishing these two matters, because they tell the caller different things:

- **An invalid credential** fails with the message `Unauthorized`, which API
  Gateway maps to **401**. The caller learns their credential is wrong.
- **A failure to read keys** is returned as an ordinary error, which becomes a
  **500**. The caller learns the fault is at this end and retries, rather than
  concluding their credential is bad and giving up.

If keys were read successfully at some earlier point and a later refresh fails,
the cached keys are used and the error is discarded. Keys change rarely, so a
parameter store outage should not become dropped requests.

Startup is strict by contrast: a missing or unparseable configuration exits
non-zero rather than starting a function that would reject every caller.

Nothing logs the credential or any part of it. Logs outlive a token's useful
life, and a bearer token in a log is a bearer token for whoever can read it.

## Key rotation

With two parameters configured, rotation drops nothing:

1. Write the new key into the secondary parameter. Both are now accepted.
2. Change the key at the sender.
3. Promote the new key to the primary parameter.
4. Clear the secondary parameter.

Each step is picked up within `KEY_CACHE_TTL`.

## Images

| Tag | Published by | Meaning |
| --- | --- | --- |
| `vX.Y.Z`, `X.Y`, `X` | tag push | An immutable release. Signed, with an SBOM and build provenance. |
| `latest` | tag push | The most recent release. |
| `edge` | push to `main`, weekly rebuild | The tip of `main`. Not signed. The weekly rebuild picks up base-image patches. |
| `sha-<commit>` | push to `main`, weekly rebuild | A specific commit. |

`latest` is deliberately published only by a release, never from the tip of
`main`, so it always names a version that was tagged, signed and attested.

**Deployments should reference a digest, not a tag.** Every tag here can move,
`latest` and `edge` included, and the weekly rebuild moves `edge` by design.
AWS Lambda in particular cannot pull from Docker Hub or ECR Public at all, so a
Lambda deployment has to copy a pinned digest into a private ECR repository in
the same account and region first.

### Verifying a release

Signatures are Sigstore keyless, so there is no public key to distribute; the
identity of the workflow that built the image is the trust anchor. Verification
needs cosign v3+ and gh v2.49+.

```sh
export IMAGE="docker.io/andreswebs/jwt-authorizer-lambda"
export VERSION="v1.0.0"
export DIGEST="$(crane digest "${IMAGE}:${VERSION}")"
```

Signature:

```sh
cosign verify \
  --certificate-identity-regexp "https://github.com/andreswebs/jwt-authorizer-lambda/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${IMAGE}@${DIGEST}"
```

Build provenance:

```sh
gh attestation verify "oci://${IMAGE}:${VERSION}" --repo andreswebs/jwt-authorizer-lambda
```

SBOM:

```sh
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity-regexp "https://github.com/andreswebs/jwt-authorizer-lambda/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${IMAGE}@${DIGEST}"
```

## Development

Everything runs through `make`, and CI calls the same targets, so the local
gate and the pipeline cannot drift:

| Command | Purpose |
| --- | --- |
| `make build` | The full gate: `validate` then compile to `bin/` |
| `make validate` | `fmt-check`, `vet`, `lint`, `tidy-check`, `test` |
| `make test` / `make test-race` | Tests, optionally under the race detector |
| `make lint` | `golangci-lint run ./...` |
| `make fmt` | Format with `gofmt -w` |
| `make tidy` | `go mod tidy` |
| `make image` | Build the container for the host platform |
| `make clean` | Remove `bin/` |

Run `make build` before considering a change complete. The suite is offline and
needs no AWS account.

### Layout

```txt
main.go              # wiring only: configuration, AWS clients, lambda.Start
internal/jwt         # HS256 verification. No AWS dependencies.
internal/authorizer  # authorizer event to IAM policy
internal/keys        # signing keys and issuer, read from SSM and cached
internal/config      # environment parsing
```

`internal/jwt` is where the security decision is made, and it deliberately
imports nothing but the standard library, so it can be read and tested on its
own terms.

### Local invocation

Running the real image against real parameters, through the Lambda Runtime
Interface Emulator:

```sh
export PLATFORM="linux/arm64"
export ARCH="arm64"
export IMG="jwt-authorizer-lambda:local"

./.scripts/update-lambda-rie.sh
./.scripts/build.sh

export SIGNING_KEY_PARAMETERS="/example/signing-key"
export EXPECTED_ISSUER_PARAMETER="/example/issuer"
./.scripts/run.sh
```

Then invoke it with an event. The generators mint a matching token, so the key
used locally has to be the one held in the parameter:

```sh
export SIGNING_KEY="the-same-value-as-the-parameter"
export ISSUER="org_123"
export METHOD_ARN="arn:aws:execute-api:us-east-1:123456789012:abcdef123/default/POST/"

./.events/event.token.json.sh > "${EVENT}"
./.scripts/test.sh
```

`.events/event.failure.example.json` holds a token claiming `alg: none`, which
must be refused.

## Authors

**Andre Silva** - [@andreswebs](https://github.com/andreswebs)

## License

This project is licensed under the [Unlicense](UNLICENSE).
