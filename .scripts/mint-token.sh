#!/usr/bin/env bash
#
# Mint an HS256 JWT for local testing.
#
# Reads SIGNING_KEY and ISSUER from the environment; TTL is optional and, when
# set to a number of seconds, adds an exp claim.

set -o nounset
set -o errexit
set -o pipefail

b64url() {
    openssl base64 -A | tr '+/' '-_' | tr -d '='
}

header=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)

if [ -n "${TTL:-}" ]; then
    exp=$(($(date +%s) + TTL))
    claims=$(printf '{"iss":"%s","exp":%d}' "${ISSUER}" "${exp}")
else
    claims=$(printf '{"iss":"%s"}' "${ISSUER}")
fi

payload=$(printf '%s' "${claims}" | b64url)
signing="${header}.${payload}"
signature=$(printf '%s' "${signing}" | openssl dgst -sha256 -hmac "${SIGNING_KEY}" -binary | b64url)

printf '%s.%s\n' "${signing}" "${signature}"
