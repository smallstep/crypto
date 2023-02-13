package tpm

import "context"

type contextKey struct{}

func NewContext(ctx context.Context, t *TPM) context.Context {
	return context.WithValue(ctx, contextKey{}, t)
}

func FromContext(ctx context.Context) *TPM {
	return ctx.Value(contextKey{}).(*TPM)
}
