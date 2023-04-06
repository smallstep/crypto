package tpm

import "context"

type contextKey struct{}

// NewContext adds TPM `t` to the context.
func NewContext(ctx context.Context, t *TPM) context.Context {
	return context.WithValue(ctx, contextKey{}, t)
}

// FromContext returns a TPM from the context.
//
// It panics when there's no TPM in the context.
func FromContext(ctx context.Context) *TPM {
	return ctx.Value(contextKey{}).(*TPM)
}

type internalCallContextKey struct{}

func internalCall(ctx context.Context) context.Context {
	return context.WithValue(ctx, internalCallContextKey{}, true)
}

func isInternalCall(ctx context.Context) bool {
	v, ok := ctx.Value(internalCallContextKey{}).(bool)
	return ok && v
}

type goTPMCallContextKey struct{}

func goTPMCall(ctx context.Context) context.Context {
	return context.WithValue(ctx, goTPMCallContextKey{}, true)
}

func isGoTPMCall(ctx context.Context) bool {
	v, ok := ctx.Value(goTPMCallContextKey{}).(bool)
	return ok && v
}
