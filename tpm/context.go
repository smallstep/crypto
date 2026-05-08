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

type machineKeyContextKey struct{}

// withMachineKey annotates ctx with a machine-key flag that the TPM open
// path consults when initializing the underlying attest.TPM. This lets
// individual key operations (CreateKey, GetKey/Public/Signer/...,
// DeleteKey) request machine-scoped vs user-scoped behaviour without
// turning MachineKey into a per-TPM-instance setting.
func withMachineKey(ctx context.Context, machineKey bool) context.Context {
	return context.WithValue(ctx, machineKeyContextKey{}, machineKey)
}

// machineKeyFromContext returns the machine-key flag annotated on ctx, or
// false if none is set.
func machineKeyFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(machineKeyContextKey{}).(bool)
	return v
}
