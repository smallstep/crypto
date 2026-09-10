# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Overview

`go.step.sm/crypto` is Smallstep's shared cryptography library (Apache-2.0). It is a
library only, no binaries: X.509 and SSH certificate templating, key generation and
PEM/JWK handling, a pluggable KMS abstraction (software, AWS, GCP, Azure, PKCS #11,
YubiKey, ssh-agent, TPM, macOS Keychain, Windows CAPI), and TPM 2.0 attestation.
[`step`](https://github.com/smallstep/cli) and [`step-ca`](https://github.com/smallstep/certificates)
are the main consumers; changes here ship to them by bumping the dependency, so keep
exported APIs backward compatible. `go.mod` requires Go 1.26; CI tests `stable` and
`oldstable`.

## Commands

```bash
make bootstrap      # install golangci-lint, govulncheck, gotestsum into $(go env GOPATH)/bin
go build ./...      # compiles everything, ~15s cold
make test           # defaulttest + simulatortest + combined coverage.out (what CI runs)
make defaulttest    # gotestsum ./... with coverage (~4000 tests, ~40s on a laptop)
make simulatortest  # CGO_ENABLED=1, -tags tpmsimulator, ./tpm and ./kms/tpmkms only (~10s)
make race           # gotestsum -race ./...
make fmt            # goimports -local go.step.sm/crypto
make lint           # golangci-lint (config curled from smallstep/workflows) + govulncheck
make generate       # go generate ./... (only the azurekms mock)
```

Single test / single package:

```bash
go test -run TestNewCertificate ./x509util/
CGO_ENABLED=1 go test -tags tpmsimulator -run TestTPM_CreateAK ./tpm/
```

`make test` and `make race` need `gotestsum` on `PATH`; `make lint` needs network
access to fetch `.golangci.yml`. Coverage output (`*.out`) is gitignored. There is no `go.work`, no submodules, and nothing in
the default test run needs cloud credentials or hardware. CI (`.github/workflows/ci.yml`)
calls the shared `smallstep/workflows` `goCI.yml` with `V=1 make test`, CodeQL, and
`libpcsclite-dev` installed for the cgo YubiKey backend.

Regenerating the NSS column map: `make -C nssdb columns` (needs an NSS source
checkout inside `nssdb/generate/`, see `nssdb/README.md`).

## Generated Code - Do Not Edit

| Pattern | Generator |
|---------|-----------|
| `kms/azurekms/internal/mock/key_vault_client.go` | mockgen, `go:generate` directive in `kms/azurekms/key_vault_test.go` |
| `nssdb/columns.go` | `nssdb/generate/main.go` via `make -C nssdb columns` |

## Package Map

```
crypto/
├── x509util/       # X.509 certs/CSRs from JSON templates (DefaultLeafTemplate, etc.), name/extension helpers
├── sshutil/        # SSH certs from JSON templates, same template engine
├── keyutil/        # key generation (RSA/EC/Ed25519/X25519/ML-DSA), key type checks
├── pemutil/        # parse/serialize keys, certs, CSRs to PEM; PKCS #8, encrypted keys
├── jose/           # go-jose/v3 wrapper: JWT, JWK, JWKSet parse/generate/validate, JWE
├── randutil/       # random strings, salts
├── tlsutil/        # tls.Config helpers, renewers
├── fingerprint/    # X.509 / SSH fingerprint encodings
├── minica/         # tiny in-memory CA, handy for tests
├── x25519/         # X25519 keys + XEdDSA signatures
├── mldsa/          # temporary shim: alias of crypto/mldsa on go1.27, stubs below (remove at go1.27 floor)
├── fipsutil/       # reports FIPS 140-3 mode (Go-version build tags)
├── nssdb/          # write certs/keys into NSS sqlite databases (cert9.db/key4.db)
├── kms/            # KMS abstraction, see below
├── tpm/            # TPM 2.0 abstraction over go-tpm / go-attestation, see below
├── internal/       # darwin/ (cgo CoreFoundation+Security), templates/ (shared FuncMap), testutil/, utils/
├── examples/       # cloudkms-attestation sample program
└── tools.go        # pins go.uber.org/mock/mockgen for go generate
```

### kms

`kms/apiv1` defines the interfaces (`KeyManager`, `CertificateManager`,
`Decrypter`, `Attester`, `SearchableKeyManager`, ...) plus `Options` and the request
types. Each backend registers a constructor in `init()` via `apiv1.Register(apiv1.Type,
fn)`; `kms.New(ctx, opts)` looks the type up from `opts.Type` or the URI scheme.
`kms/kms.go` only imports `softkms`, so a program must blank-import every backend it
wants (`_ "go.step.sm/crypto/kms/pkcs11"`). Backends are configured by URI
(`pkcs11:token=...?pin-value=...`, `tpmkms:device=/dev/tpmrm0`, `yubikey:pin-value=...`);
`kms/uri` parses them with `;`-separated opaque params and `?` query params.

| Backend | URI scheme | Needs | Opt-out tag |
|---------|-----------|-------|-------------|
| `softkms` | `softkms:` | nothing (default, always linked) | - |
| `awskms` / `cloudkms` / `azurekms` | `awskms:` / `cloudkms:` / `azurekms:` | pure Go cloud SDKs | `noawskms` / `nocloudkms` / `noazurekms` |
| `sshagentkms` | `sshagentkms:` | `SSH_AUTH_SOCK` at runtime | `nosshagentkms` |
| `tpmkms` | `tpmkms:` | pure Go; a TPM at runtime | `notpmkms` |
| `pkcs11` | `pkcs11:` | **cgo** (crypto11 / miekg/pkcs11) | `nopkcs11` |
| `yubikey` | `yubikey:` | **cgo** (piv-go; `libpcsclite-dev` on Linux) | `noyubikey` |
| `mackms` | `mackms:` | **darwin && cgo** (CoreFoundation, Security frameworks) | `nomackms` |
| `capi` | `capi:` | **windows** only | `nocapi` |
| `platform` | `kms:` | dispatches to mackms (darwin), capi (windows), tpmkms (else); `backend=` overrides | - |

When a backend is excluded by tag or platform, its `no_*.go` / `*_no_cgo.go` stub still
registers the type so `kms.New` returns a clear "not supported" error instead of
"unsupported kms type". Add both halves when adding a backend.

### tpm

`tpm.TPM` wraps `google/go-tpm` and `smallstep/go-attestation`: EK/AK/application key
lifecycle, info/caps, `tpm/storage` persistence (`dirstore`, `filestore`, `tpmstore`,
`feedthrough`, `blackhole`), `tpm/tss2` (TPM 2.0 key file ASN.1 per draft-bottomley),
`tpm/attestation` (HTTP client to an attestation CA), `tpm/skae` (subject key attestation
evidence extension), `tpm/simulator` (go-tpm-tools simulator, compiled only with
`-tags tpmsimulator`). Platform-specific device open/close/socket code lives in
`tpm/internal/`. `kms/tpmkms` is the KMS backend built on top.

## Build Tags

| Tag | Effect |
|-----|--------|
| `tpmsimulator` | compile the software TPM and simulator-backed tests (`tpm`, `kms/tpmkms`, `kms/platform`, `tpm/tss2`, `tpm/rand`, `tpm/attestation`); needs `CGO_ENABLED=1` |
| `tpm` | `tpm/tss2` tests against a real TPM device |
| `softhsm2` / `yubihsm2` / `opensc` | `kms/pkcs11` tests against that module (skipped if the `.so`/`.dylib` is not found) |
| `no<backend>` | drop a KMS backend, see table above |
| `go1.27`, `go1.24`, `go1.26` | ML-DSA (`crypto/mldsa`), FIPS reporting, and CSR signature-algorithm handling differ by toolchain; keep the `_go1XX.go` / `_stub.go` / `_other.go` pairs in sync |

Tests that touch real resources in the default run: `kms/mackms` on macOS creates and
deletes keys in the login keychain; `kms/sshagentkms` spawns a real `ssh-agent`
(skipped with `-short`); `kms/yubikey` and `kms/pkcs11` compile under cgo but skip
without hardware. Cloud backend tests use fakes and never call out.

## Conventions

- **Errors**: mixed. Older packages (`x509util`, `sshutil`, `pemutil`, `jose`, `kms/uri`,
  the cloud backends) use `github.com/pkg/errors` (`errors.Wrap`, `errors.Errorf`);
  newer code (`tpm/`, `mackms`, `platform`, `mldsa`) uses `fmt.Errorf("...: %w", err)`.
  Match the file you are editing; use `fmt.Errorf` with `%w` in new packages.
  `apiv1.NotFoundError` / `apiv1.AlreadyExistsError` are the sentinel types backends return.
- **No logging framework**; this is a library. Do not add one.
- **Tests**: `testify` (`assert`/`require`), table-driven `t.Run` loops, fixtures under
  each package's `testdata/`. `gomock` is used only for the Azure Key Vault client.
  `minica` and `internal/testutil` are the shared helpers.
- **Templates**: `x509util` and `sshutil` render JSON via `text/template` with the
  `internal/templates` FuncMap (sprig plus `toTime`, `formatTime`, etc.); the `fail`
  function surfaces user-visible template errors. The `Default*Template` constants are
  consumed verbatim by `step-ca` provisioners, so changing them is a behavior change.
- **Imports**: `goimports -local go.step.sm/crypto`; lint rules come from the shared
  `smallstep/workflows/.golangci.yml`, not a file in this repo.
- **Releases**: pushing a `v*` tag runs CI and creates a GitHub release. Tag only from
  `master`; `go.mod` retracts `v0.77.3` - `v0.77.7` because they were tagged from a branch.
  Consumers pin by version, so local cross-repo work uses
  `replace go.step.sm/crypto => ../crypto` in the consumer's `go.mod` (never commit it).
