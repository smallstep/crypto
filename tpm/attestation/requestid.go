package attestation

import (
	"context"
	"net/http"

	"go.step.sm/crypto/randutil"
)

type requestIDContextKey struct{}

// NewRequestIDContext returns a new context with the given request ID added to the
// context.
func NewRequestIDContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

// RequestIDFromContext returns the request ID from the context if it exists.
// and is not empty.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(requestIDContextKey{}).(string)
	return v, ok && v != ""
}

// requestIDHeader is the header name used for propagating request IDs from
// the attestation client to the attestation CA and back again.
const requestIDHeader = "X-Request-Id"

// newRequestID generates a new random UUIDv4 request ID. If it fails,
// the request ID will be the empty string.
func newRequestID() string {
	return randutil.UUIDv4()
}

// enforceRequestID checks if the X-Request-Id HTTP header is filled. If it's
// empty, the context is searched for a request ID. If that's also empty, a new
// request ID is generated.
func enforceRequestID(r *http.Request) {
	if requestID := r.Header.Get(requestIDHeader); requestID == "" {
		if reqID, ok := RequestIDFromContext(r.Context()); ok {
			requestID = reqID
		} else {
			requestID = newRequestID()
		}
		r.Header.Set(requestIDHeader, requestID)
	}
}
