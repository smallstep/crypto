package tpm

import "context"

type contextKey struct{}

func NewContext(ctx context.Context, t *TPM) context.Context {
	return context.WithValue(ctx, contextKey{}, t)
}

func FromContext(ctx context.Context) *TPM {
	return ctx.Value(contextKey{}).(*TPM)
}

type internalCallContextKey struct{}

func internalCall(ctx context.Context) context.Context {
	return context.WithValue(ctx, internalCallContextKey{}, true)
}

func isInternalCall(ctx context.Context) bool {
	if v, ok := ctx.Value(internalCallContextKey{}).(bool); ok {
		return v
	}
	return false
}

type goTPMCallContextKey struct{}

func goTPMCall(ctx context.Context) context.Context {
	return context.WithValue(ctx, goTPMCallContextKey{}, true)
}

func isGoTPMCall(ctx context.Context) bool {
	if v, ok := ctx.Value(goTPMCallContextKey{}).(bool); ok {
		return v
	}
	return false
}
