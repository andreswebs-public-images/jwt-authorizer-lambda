#!/usr/bin/env bash
#
# A REQUEST authorizer event carrying the same credential in a header.

set -o nounset
set -o errexit
set -o pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR

token=$("${SCRIPT_DIR}/../.scripts/mint-token.sh")

cat <<EOT
{
  "type": "REQUEST",
  "methodArn": "${METHOD_ARN}",
  "headers": {
    "${HEADER_KEY:-Authorization}": "Bearer ${token}"
  }
}
EOT
