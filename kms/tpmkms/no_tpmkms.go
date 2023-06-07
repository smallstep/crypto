//go:build notpmkms
// +build notpmkms

package tpmkms

func init() {
	apiv1.Register(apiv1.TPMKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		name := filepath.Base(os.Args[0])
		return nil, errors.Errorf("unsupported KMS type 'tpmkms': %s is compiled without TPM KMS support", name)
	})
}
