package authorizer

import "errors"

// ErrUnauthorized rejects a request as unauthenticated.
//
// API Gateway maps an authorizer failure to 401 only when the error message is
// exactly "Unauthorized". Any other message produces 500, which would report an
// invalid credential as a fault on this side and encourage the caller to retry
// a request that can never succeed.
var ErrUnauthorized = errors.New("Unauthorized")
