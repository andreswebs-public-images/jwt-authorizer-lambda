#!/usr/bin/env bash
#
# A TOKEN authorizer event carrying a freshly minted, valid credential.

set -o nounset
set -o errexit
set -o pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR

token=$("${SCRIPT_DIR}/../.scripts/mint-token.sh")

cat <<EOT
{
  "type": "TOKEN",
  "methodArn": "${METHOD_ARN}",
  "authorizationToken": "Bearer ${token}"
}
EOT
