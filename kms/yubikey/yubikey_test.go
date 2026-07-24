//go:build cgo

package yubikey

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
)

type stubPivKey struct {
	attestCA      *minica.CA
	attestSigner  privateKey
	userCA        *minica.CA
	keyInfoMap    map[piv.Slot]piv.KeyInfo
	attestMap     map[piv.Slot]*x509.Certificate
	certMap       map[piv.Slot]*x509.Certificate
	signerMap     map[piv.Slot]interface{}
	keyOptionsMap map[piv.Slot]piv.Key
	serial        uint32
	serialErr     error
	closeErr      error
	closed        int
}

type symmetricAlgorithm int

const (
	ECDSA symmetricAlgorithm = iota
	RSA
)
const rsaKeySize = 2048

type privateKey interface {
	crypto.PrivateKey

	Public() crypto.PublicKey
}

//nolint:typecheck // ignore deadcode warnings
func newStubPivKey(t *testing.T, alg symmetricAlgorithm) *stubPivKey {
	var (
		attSigner  privateKey
		userSigner privateKey
	)
	t.Helper()

	attestCA, err := minica.New()
	if err != nil {
		t.Fatal(err)
	}
	userCA, err := minica.New()
	if err != nil {
		t.Fatal(err)
	}

	var keyInfoAlgo piv.Algorithm
	switch alg {
	case ECDSA:
		keyInfoAlgo = piv.AlgorithmEC256
		attSigner, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		userSigner, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	case RSA:
		keyInfoAlgo = piv.AlgorithmRSA2048
		attSigner, err = rsa.GenerateKey(rand.Reader, rsaKeySize)
		if err != nil {
			t.Fatal(err)
		}
		userSigner, err = rsa.GenerateKey(rand.Reader, rsaKeySize)
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal(errors.New("unknown alg"))
	}

	sn := 112233
	snAsn1, err := asn1.Marshal(sn)
	if err != nil {
		t.Fatal(err)
	}
	attCert, err := attestCA.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "attested certificate"},
		PublicKey: attSigner.Public(),
		ExtraExtensions: []pkix.Extension{
			{Id: oidYubicoSerialNumber, Value: snAsn1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	userCert, err := userCA.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "test.example.org"},
		DNSNames:  []string{"test.example.org"},
		PublicKey: userSigner.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}

	return &stubPivKey{
		attestCA:     attestCA,
		attestSigner: attSigner,
		userCA:       userCA,
		keyInfoMap: map[piv.Slot]piv.KeyInfo{
			piv.SlotKeyManagement: {
				PublicKey:   attSigner.Public(),
				Algorithm:   keyInfoAlgo,
				PINPolicy:   piv.PINPolicyOnce,
				TouchPolicy: piv.TouchPolicyCached,
				Origin:      piv.OriginGenerated,
			}, // 9d
		},
		attestMap: map[piv.Slot]*x509.Certificate{
			piv.SlotAuthentication: attCert, // 9a
		},
		certMap: map[piv.Slot]*x509.Certificate{
			piv.SlotSignature: userCert,              // 9c
			slotAttestation:   attestCA.Intermediate, // f9
		},
		signerMap: map[piv.Slot]interface{}{
			piv.SlotAuthentication: attSigner,  // 9a
			piv.SlotSignature:      userSigner, // 9c
		},
		keyOptionsMap: map[piv.Slot]piv.Key{},
		serial:        uint32(sn),
	}
}

func (s *stubPivKey) KeyInfo(slot piv.Slot) (piv.KeyInfo, error) {
	keyInfo, ok := s.keyInfoMap[slot]
	if !ok {
		return piv.KeyInfo{}, errors.New("public key not found")
	}
	return keyInfo, nil
}

func (s *stubPivKey) Certificate(slot piv.Slot) (*x509.Certificate, error) {
	cert, ok := s.certMap[slot]
	if !ok {
		if slot == slotMapping["82"] {
			return nil, errors.New("command failed: some error")
		}
		return nil, fmt.Errorf("command failed: %w", piv.ErrNotFound)
	}
	return cert, nil
}

func (s *stubPivKey) SetCertificate(key []byte, slot piv.Slot, cert *x509.Certificate) error {
	if !bytes.Equal(piv.DefaultManagementKey, key) {
		return errors.New("missing or invalid management key")
	}
	s.certMap[slot] = cert
	return nil
}

func (s *stubPivKey) GenerateKey(key []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	if !bytes.Equal(piv.DefaultManagementKey, key) {
		return nil, errors.New("missing or invalid management key")
	}

	var signer crypto.Signer
	switch opts.Algorithm {
	case piv.AlgorithmEC256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = key
	case piv.AlgorithmEC384:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = key
	case piv.AlgorithmEd25519:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = key
	case piv.AlgorithmRSA1024:
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return nil, err
		}
		signer = key
	case piv.AlgorithmRSA2048:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		signer = key
	case piv.AlgorithmRSA3072:
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, err
		}
		signer = key
	case piv.AlgorithmRSA4096:
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}
		signer = key
	default:
		return nil, errors.New("unsupported algorithm")
	}

	s.signerMap[slot] = signer
	s.keyOptionsMap[slot] = opts
	return signer.Public(), nil
}

func (s *stubPivKey) PrivateKey(slot piv.Slot, public crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error) {
	if auth.PIN != "123456" {
		return nil, errors.New("missing or invalid pin")
	}
	key, ok := s.signerMap[slot]
	if !ok {
		return nil, errors.New("private key not found")
	}
	return key, nil
}

func (s *stubPivKey) Attest(slot piv.Slot) (*x509.Certificate, error) {
	cert, ok := s.attestMap[slot]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return cert, nil
}

func (s *stubPivKey) Close() error {
	s.closed++
	return s.closeErr
}

func (s *stubPivKey) Serial() (uint32, error) {
	if s.serialErr != nil {
		return 0, s.serialErr
	}
	return s.serial, nil
}

func TestRegister(t *testing.T) {
	pCards := pivCards
	t.Cleanup(func() {
		pivCards = pCards
	})

	pivCards = func() ([]string, error) {
		return []string{"Yubico YubiKey OTP+FIDO+CCID"}, nil
	}

	fn, ok := apiv1.LoadKeyManagerNewFunc(apiv1.YubiKey)
	if !ok {
		t.Fatal("YubiKey is not registered")
	}
	_, _ = fn(context.Background(), apiv1.Options{
		Type: "YubiKey", URI: "yubikey:",
	})
}

func TestNew(t *testing.T) {
	ctx := t.Context()
	pOpen := pivOpen
	pCards := pivCards
	t.Cleanup(func() {
		pivMap = sync.Map{}
		pivOpen = pOpen
		pivCards = pCards
	})

	managementKey, err := randutil.Salt(24) // DES3 and AES192
	require.NoError(t, err)
	managementKeyFile := filepath.Join(t.TempDir(), "management.key")
	require.NoError(t, os.WriteFile(managementKeyFile, []byte(hex.EncodeToString(managementKey)), 0600))
	aes128ManagementKey, err := randutil.Salt(16)
	require.NoError(t, err)
	aes256ManagementKey, err := randutil.Salt(32)
	require.NoError(t, err)

	yk := newStubPivKey(t, ECDSA)

	okPivCards := func() ([]string, error) {
		return []string{"Yubico YubiKey OTP+FIDO+CCID"}, nil
	}
	okMultiplePivCards := func() ([]string, error) {
		return []string{
			"Yubico YubiKey OTP+FIDO+CCID",
			"Yubico YubiKey OTP+FIDO+CCID 01",
		}, nil
	}
	okBuiltInReaderPivCards := func() ([]string, error) {
		return []string{
			"Broadcom Corp Contacted SmartCard 0",
			"Broadcom Corp Contactless SmartCard 0",
			"Yubico Yubikey 4 OTP+U2F+CCID 0",
		}, nil
	}
	okOtherReaderPivCards := func() ([]string, error) {
		return []string{"Nitrokey Nitrokey 3 [CCID/ICCD Interface] 00 00"}, nil
	}
	failPivCards := func() ([]string, error) {
		return nil, errors.New("error reading cards")
	}
	failNoPivCards := func() ([]string, error) {
		return []string{}, nil
	}

	okPivOpen := func(card string) (pivKey, error) {
		return yk, nil
	}
	// okYubiKeyPivOpen fails on the readers that don't identify a YubiKey, the
	// way an empty reader fails in the smart card service.
	okYubiKeyPivOpen := func(card string) (pivKey, error) {
		if !isYubiKey(card) {
			return nil, errors.New("connecting to smart card: the smart card has been removed, so further communication is not possible")
		}
		return yk, nil
	}
	failPivOpen := func(card string) (pivKey, error) {
		return nil, errors.New("error opening card")
	}

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		setup   func()
		want    *YubiKey
		wantErr bool
	}{
		{"ok", args{ctx, apiv1.Options{}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "123456", card: "Yubico YubiKey OTP+FIDO+CCID", managementKey: piv.DefaultManagementKey}, false},
		{"ok with uri", args{ctx, apiv1.Options{
			URI: "yubikey:pin-value=111111;management-key=001122334455667788990011223344556677889900112233",
		}}, func() {
			pivMap = sync.Map{}
			pivCards = okMultiplePivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "111111", card: "Yubico YubiKey OTP+FIDO+CCID", managementKey: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33}}, false},
		{"ok with uri and serial", args{ctx, apiv1.Options{
			URI: "yubikey:serial=112233?pin-value=123456",
		}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "123456", card: "Yubico YubiKey OTP+FIDO+CCID", managementKey: piv.DefaultManagementKey}, false},
		{"ok with uri and serial from cache", args{ctx, apiv1.Options{
			URI: "yubikey:serial=112233?pin-value=123456",
		}}, func() {
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "123456", card: "Yubico YubiKey OTP+FIDO+CCID", managementKey: piv.DefaultManagementKey}, false},
		{"ok with management-key-source", args{ctx, apiv1.Options{
			URI: fmt.Sprintf("yubikey:management-key-source=%s?pin-value=123456", managementKeyFile),
		}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "123456", card: "Yubico YubiKey OTP+FIDO+CCID", managementKey: managementKey}, false},
		{"ok with AES128 management key", args{ctx, apiv1.Options{
			URI: fmt.Sprintf("yubikey:management-key=%s?pin-value=123456", hex.EncodeToString(aes128ManagementKey)),
		}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "123456", card: "Yubico YubiKey OTP+FIDO+CCID", managementKey: aes128ManagementKey}, false},
		{"ok with AES256 management key", args{ctx, apiv1.Options{
			URI: fmt.Sprintf("yubikey:management-key=%s?pin-value=123456", hex.EncodeToString(aes256ManagementKey)),
		}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "123456", card: "Yubico YubiKey OTP+FIDO+CCID", managementKey: aes256ManagementKey}, false},
		{"ok with Pin", args{ctx, apiv1.Options{Pin: "222222"}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "222222", card: "Yubico YubiKey OTP+FIDO+CCID", managementKey: piv.DefaultManagementKey}, false},
		{"ok with ManagementKey", args{ctx, apiv1.Options{ManagementKey: "001122334455667788990011223344556677889900112233"}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "123456", card: "Yubico YubiKey OTP+FIDO+CCID", managementKey: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33}}, false},
		{"ok with built-in reader", args{ctx, apiv1.Options{}}, func() {
			pivMap = sync.Map{}
			pivCards = okBuiltInReaderPivCards
			pivOpen = okYubiKeyPivOpen
		}, &YubiKey{yk: yk, pin: "123456", card: "Yubico Yubikey 4 OTP+U2F+CCID 0", managementKey: piv.DefaultManagementKey}, false},
		{"ok with other reader", args{ctx, apiv1.Options{}}, func() {
			pivMap = sync.Map{}
			pivCards = okOtherReaderPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "123456", card: "Nitrokey Nitrokey 3 [CCID/ICCD Interface] 00 00", managementKey: piv.DefaultManagementKey}, false},
		{"fail uri", args{ctx, apiv1.Options{URI: "badschema:"}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, nil, true},
		{"fail management key", args{ctx, apiv1.Options{URI: "yubikey:management-key=xxyyzz"}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, nil, true},
		{"fail management key size", args{ctx, apiv1.Options{URI: "yubikey:management-key=00112233"}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, nil, true},
		{"fail management key source", args{ctx, apiv1.Options{URI: "yubikey:management-key-source=missing.txt"}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, nil, true},
		{"fail pivCards", args{ctx, apiv1.Options{}}, func() {
			pivMap = sync.Map{}
			pivCards = failPivCards
			pivOpen = okPivOpen
		}, nil, true},
		{"fail no pivCards", args{ctx, apiv1.Options{}}, func() {
			pivMap = sync.Map{}
			pivCards = failNoPivCards
			pivOpen = okPivOpen
		}, nil, true},
		{"fail no pivCards with serial", args{ctx, apiv1.Options{
			URI: "yubikey:pin-value=111111;serial=332211?pin-value=123456",
		}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, nil, true},
		{"fail pivOpen", args{ctx, apiv1.Options{}}, func() {
			pivMap = sync.Map{}
			pivCards = okPivCards
			pivOpen = failPivOpen
		}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNew_cardSafety verifies that New does not connect to the readers built in
// a laptop, even if a card in them could be opened, as opening a card takes
// exclusive access to it.
func TestNew_cardSafety(t *testing.T) {
	pOpen := pivOpen
	pCards := pivCards
	t.Cleanup(func() {
		pivMap = sync.Map{}
		pivOpen = pOpen
		pivCards = pCards
	})

	yk := newStubPivKey(t, ECDSA)

	var opened []string
	pivMap = sync.Map{}
	pivCards = func() ([]string, error) {
		return []string{
			"Broadcom Corp Contacted SmartCard 0",
			"Broadcom Corp Contactless SmartCard 0",
			"Yubico Yubikey 4 OTP+U2F+CCID 0",
		}, nil
	}
	pivOpen = func(card string) (pivKey, error) {
		opened = append(opened, card)
		return yk, nil
	}

	k, err := New(t.Context(), apiv1.Options{})
	require.NoError(t, err)
	assert.Equal(t, "Yubico Yubikey 4 OTP+U2F+CCID 0", k.card)
	assert.Equal(t, []string{"Yubico Yubikey 4 OTP+U2F+CCID 0"}, opened)
}

func Test_selectCard(t *testing.T) {
	pOpen := pivOpen
	t.Cleanup(func() {
		pivMap = sync.Map{}
		pivOpen = pOpen
	})

	const (
		contacted     = "Broadcom Corp Contacted SmartCard 0"
		contactless   = "Broadcom Corp Contactless SmartCard 0"
		yubiKey       = "Yubico Yubikey 4 OTP+U2F+CCID 0"
		otherYubiKey  = "Yubico YubiKey OTP+FIDO+CCID 01"
		brokenYubiKey = "Yubico YubiKey OTP+FIDO+CCID 02"
		nitroKey      = "Nitrokey Nitrokey 3 [CCID/ICCD Interface] 00 00"
	)

	keys := map[string]*stubPivKey{}
	for card, serial := range map[string]uint32{
		contacted:    100001,
		contactless:  100002,
		yubiKey:      112233,
		otherYubiKey: 332211,
		nitroKey:     445566,
	} {
		k := newStubPivKey(t, ECDSA)
		k.serial = serial
		keys[card] = k
	}
	// A YubiKey that cannot report its serial number.
	keys[brokenYubiKey] = newStubPivKey(t, ECDSA)
	keys[brokenYubiKey].serialErr = errors.New("error getting serial number")

	type args struct {
		cards  []string
		serial string
	}
	tests := []struct {
		name       string
		args       args
		open       []string
		want       string
		wantOpened []string
		wantClosed map[string]int
		wantCached []string
		wantErr    bool
	}{
		{"ok", args{[]string{yubiKey}, ""},
			[]string{yubiKey}, yubiKey,
			[]string{yubiKey}, nil, []string{yubiKey}, false},
		{"ok with built-in reader", args{[]string{contacted, contactless, yubiKey}, ""},
			[]string{contacted, contactless, yubiKey}, yubiKey,
			[]string{yubiKey}, nil, []string{yubiKey}, false},
		{"ok with built-in reader and serial", args{[]string{contacted, contactless, yubiKey}, "112233"},
			[]string{contacted, contactless, yubiKey}, yubiKey,
			[]string{yubiKey}, nil, []string{yubiKey}, false},
		{"ok with built-in readers only", args{[]string{contacted, contactless}, ""},
			[]string{contacted, contactless}, contacted,
			[]string{contacted}, nil, []string{contacted}, false},
		{"ok with multiple yubikeys", args{[]string{yubiKey, otherYubiKey}, ""},
			[]string{yubiKey, otherYubiKey}, yubiKey,
			[]string{yubiKey}, nil, []string{yubiKey}, false},
		{"ok with multiple yubikeys and serial", args{[]string{yubiKey, otherYubiKey}, "332211"},
			[]string{yubiKey, otherYubiKey}, otherYubiKey,
			[]string{yubiKey, otherYubiKey}, map[string]int{yubiKey: 1}, []string{otherYubiKey}, false},
		{"ok with other reader", args{[]string{nitroKey}, ""},
			[]string{nitroKey}, nitroKey,
			[]string{nitroKey}, nil, []string{nitroKey}, false},
		{"ok with other reader and serial before a yubikey", args{[]string{nitroKey, yubiKey}, "445566"},
			[]string{nitroKey, yubiKey}, nitroKey,
			[]string{yubiKey, nitroKey}, map[string]int{yubiKey: 1}, []string{nitroKey}, false},
		{"ok with yubikey that cannot be opened", args{[]string{nitroKey, yubiKey}, ""},
			[]string{nitroKey}, nitroKey,
			[]string{yubiKey, nitroKey}, nil, []string{nitroKey}, false},
		{"ok with one yubikey that cannot be opened", args{[]string{contacted, yubiKey, otherYubiKey}, ""},
			[]string{contacted, otherYubiKey}, otherYubiKey,
			[]string{yubiKey, otherYubiKey}, nil, []string{otherYubiKey}, false},
		{"ok with yubikey that cannot report its serial", args{[]string{brokenYubiKey, yubiKey}, "112233"},
			[]string{brokenYubiKey, yubiKey}, yubiKey,
			[]string{brokenYubiKey, yubiKey}, map[string]int{brokenYubiKey: 1}, []string{yubiKey}, false},
		{"ok with serial behind a reader that cannot be opened", args{[]string{contacted, nitroKey}, "445566"},
			[]string{nitroKey}, nitroKey,
			[]string{contacted, nitroKey}, nil, []string{nitroKey}, false},
		{"fail no cards", args{[]string{}, ""},
			nil, "",
			nil, nil, nil, true},
		{"fail no yubikey in readers", args{[]string{contacted, contactless}, ""},
			nil, "",
			[]string{contacted}, nil, nil, true},
		{"fail yubikey that cannot be opened", args{[]string{contacted, yubiKey}, ""},
			nil, "",
			[]string{yubiKey, contacted}, nil, nil, true},
		{"fail serial not found", args{[]string{contacted, yubiKey}, "999999"},
			[]string{contacted, yubiKey}, "",
			[]string{yubiKey, contacted}, map[string]int{contacted: 1, yubiKey: 1}, nil, true},
		{"fail serial not found with a reader that cannot be opened", args{[]string{contacted, yubiKey}, "999999"},
			[]string{yubiKey}, "",
			[]string{yubiKey, contacted}, map[string]int{yubiKey: 1}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pivMap = sync.Map{}
			for _, k := range keys {
				k.closed = 0
			}

			var opened []string
			pivOpen = func(card string) (pivKey, error) {
				opened = append(opened, card)
				if !slices.Contains(tt.open, card) {
					return nil, errors.New("connecting to smart card: the smart card has been removed, so further communication is not possible")
				}
				return keys[card], nil
			}

			got, card, err := selectCard(tt.args.cards, tt.args.serial)
			if (err != nil) != tt.wantErr {
				t.Errorf("selectCard() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want == "" {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, keys[tt.want], got)
			}
			assert.Equal(t, tt.want, card)
			assert.Equal(t, tt.wantOpened, opened)

			for name, k := range keys {
				assert.Equal(t, tt.wantClosed[name], k.closed, "unexpected number of closes of %q", name)
			}

			var cached []string
			pivMap.Range(func(k, _ any) bool {
				cached = append(cached, k.(string))
				return true
			})
			assert.ElementsMatch(t, tt.wantCached, cached)
		})
	}
}

// Test_selectCard_serialNotFound verifies that the error returned when no
// YubiKey has the given serial number always names the readers that were
// scanned, even when one of them cannot be opened. An empty reader built in a
// laptop is the one that fails to open, and an error blaming only that reader,
// with no mention of the YubiKey that we did read, is the error reported in
// smallstep/crypto#649.
func Test_selectCard_serialNotFound(t *testing.T) {
	pOpen := pivOpen
	t.Cleanup(func() {
		pivMap = sync.Map{}
		pivOpen = pOpen
	})

	const (
		contacted = "Broadcom Corp Contacted SmartCard 0"
		yubiKey   = "Yubico Yubikey 4 OTP+U2F+CCID 0"
	)

	yk := newStubPivKey(t, ECDSA)
	yk.serial = 112233

	tests := []struct {
		name    string
		open    []string
		wantErr string
	}{
		{"all readers open", []string{contacted, yubiKey},
			`failed to find key with serial number 999999 in the readers "Yubico Yubikey 4 OTP+U2F+CCID 0", "Broadcom Corp Contacted SmartCard 0"`},
		{"built-in reader cannot be opened", []string{yubiKey},
			`failed to find key with serial number 999999 in the readers "Yubico Yubikey 4 OTP+U2F+CCID 0", "Broadcom Corp Contacted SmartCard 0": error opening yubikey in reader "Broadcom Corp Contacted SmartCard 0": error opening card`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pivMap = sync.Map{}
			pivOpen = func(card string) (pivKey, error) {
				if !slices.Contains(tt.open, card) {
					return nil, errors.New("error opening card")
				}
				return yk, nil
			}

			got, card, err := selectCard([]string{contacted, yubiKey}, "999999")
			assert.EqualError(t, err, tt.wantErr)
			assert.Nil(t, got)
			assert.Empty(t, card)
		})
	}
}

// Test_selectCard_serialReadError verifies that the error returned when no
// YubiKey has the given serial number reports a serial number that we could
// not read: a reader skipped because its serial read failed must not be listed
// as scanned with no trace of the failure.
func Test_selectCard_serialReadError(t *testing.T) {
	pOpen := pivOpen
	t.Cleanup(func() {
		pivMap = sync.Map{}
		pivOpen = pOpen
	})

	const (
		yubiKey       = "Yubico Yubikey 4 OTP+U2F+CCID 0"
		brokenYubiKey = "Yubico YubiKey OTP+FIDO+CCID 02"
	)

	yk := newStubPivKey(t, ECDSA)
	yk.serial = 112233
	broken := newStubPivKey(t, ECDSA)
	broken.serialErr = errors.New("error getting serial number")
	keys := map[string]*stubPivKey{yubiKey: yk, brokenYubiKey: broken}

	pivMap = sync.Map{}
	pivOpen = func(card string) (pivKey, error) {
		return keys[card], nil
	}

	got, card, err := selectCard([]string{brokenYubiKey, yubiKey}, "999999")
	assert.EqualError(t, err, `failed to find key with serial number 999999 in the readers "Yubico YubiKey OTP+FIDO+CCID 02", "Yubico Yubikey 4 OTP+U2F+CCID 0": error reading the serial number in reader "Yubico YubiKey OTP+FIDO+CCID 02": error getting serial number`)
	assert.Nil(t, got)
	assert.Empty(t, card)
	assert.Equal(t, 1, broken.closed)
	assert.Equal(t, 1, yk.closed)
}

// Test_selectCard_cached verifies that the connections loaded from the cache are
// never closed, as they are in use by another YubiKey.
func Test_selectCard_cached(t *testing.T) {
	pOpen := pivOpen
	t.Cleanup(func() {
		pivMap = sync.Map{}
		pivOpen = pOpen
	})

	const (
		yubiKey      = "Yubico Yubikey 4 OTP+U2F+CCID 0"
		otherYubiKey = "Yubico YubiKey OTP+FIDO+CCID 01"
	)

	yk := newStubPivKey(t, ECDSA)
	otherYk := newStubPivKey(t, ECDSA)
	otherYk.serial = 332211

	pivMap = sync.Map{}
	pivMap.Store(yubiKey, yk)
	pivMap.Store(otherYubiKey, otherYk)
	pivOpen = func(card string) (pivKey, error) {
		t.Errorf("pivOpen(%q) called, want the connection from the cache", card)
		return nil, errors.New("error opening card")
	}

	got, card, err := selectCard([]string{yubiKey, otherYubiKey}, "332211")
	require.NoError(t, err)
	assert.Equal(t, otherYk, got)
	assert.Equal(t, otherYubiKey, card)
	assert.Zero(t, yk.closed)
	assert.Zero(t, otherYk.closed)

	v, ok := pivMap.Load(yubiKey)
	assert.True(t, ok)
	assert.Equal(t, yk, v)
}

func TestYubiKey_LoadCertificate(t *testing.T) {
	yk := newStubPivKey(t, ECDSA)

	type fields struct {
		yk            pivKey
		pin           string
		managementKey []byte
	}
	type args struct {
		req *apiv1.LoadCertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *x509.Certificate
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.LoadCertificateRequest{
			Name: "yubikey:slot-id=9c",
		}}, yk.certMap[piv.SlotSignature], false},
		{"fail getSlot", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.LoadCertificateRequest{
			Name: "slot-id=9c",
		}}, nil, true},
		{"fail certificate", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.LoadCertificateRequest{
			Name: "yubikey:slot-id=85",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.LoadCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.LoadCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("YubiKey.LoadCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubiKey_StoreCertificate(t *testing.T) {
	yk := newStubPivKey(t, ECDSA)

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := yk.userCA.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "foo.example.org"},
		DNSNames:  []string{"foo.example.org"},
		PublicKey: signer.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		yk            pivKey
		pin           string
		managementKey []byte
	}
	type args struct {
		req *apiv1.StoreCertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.StoreCertificateRequest{
			Name:        "yubikey:slot-id=9c",
			Certificate: cert,
		}}, false},
		{"fail nil", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.StoreCertificateRequest{
			Name: "yubikey:slot-id=9c",
		}}, true},
		{"fail getSlot", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.StoreCertificateRequest{
			Name:        "slot-id=9c",
			Certificate: cert,
		}}, true},
		{"fail setCertificate", fields{yk, "123456", []byte{}}, args{&apiv1.StoreCertificateRequest{
			Name:        "yubikey:slot-id=9c",
			Certificate: cert,
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			if err := k.StoreCertificate(tt.args.req); (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.StoreCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestYubiKey_GetPublicKey(t *testing.T) {
	yk := newStubPivKey(t, ECDSA)

	type fields struct {
		yk            pivKey
		pin           string
		managementKey []byte
	}
	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"ok with keyInfo", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.GetPublicKeyRequest{
			Name: "yubikey:slot-id=9d",
		}}, yk.keyInfoMap[piv.SlotKeyManagement].PublicKey, false},
		{"ok with Attest", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.GetPublicKeyRequest{
			Name: "yubikey:slot-id=9a",
		}}, yk.attestMap[piv.SlotAuthentication].PublicKey, false},
		{"ok with certificate", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.GetPublicKeyRequest{
			Name: "yubikey:slot-id=9c",
		}}, yk.certMap[piv.SlotSignature].PublicKey, false},
		{"fail getSlot", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.GetPublicKeyRequest{
			Name: "slot-id=9c",
		}}, nil, true},
		{"fail getPublicKey", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.GetPublicKeyRequest{
			Name: "yubikey:slot-id=82",
		}}, nil, true},
		{"fail getPublicKey not found", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.GetPublicKeyRequest{
			Name: "yubikey:slot-id=85",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.GetPublicKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("YubiKey.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubiKey_CreateKey(t *testing.T) {
	yk := newStubPivKey(t, ECDSA)

	type fields struct {
		yk            pivKey
		pin           string
		managementKey []byte
	}
	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantFn  func() *apiv1.CreateKeyResponse
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok default", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=9c",
				PublicKey: yk.signerMap[slotMapping["9c"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=9c",
				},
			}
		}, false},
		{"ok p256", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok p384", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA384,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok ed25519", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.PureEd25519,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok rsa", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok rsa 1024", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               1024,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok rsa 2048", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               2048,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok rsa 3072", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SHA256WithRSAPSS,
			Bits:               3072,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok rsa 4096", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SHA512WithRSAPSS,
			Bits:               4096,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok with policies", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			PINPolicy:          apiv1.PINPolicyNever,
			TouchPolicy:        apiv1.TouchPolicyAlways,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"fail rsa 512", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               512,
		}}, func() *apiv1.CreateKeyResponse { return nil }, true},
		{"fail getSignatureAlgorithm", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SignatureAlgorithm(100),
		}}, func() *apiv1.CreateKeyResponse { return nil }, true},
		{"fail getSlotAndName", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:foo=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, func() *apiv1.CreateKeyResponse { return nil }, true},
		{"fail generateKey", fields{yk, "123456", []byte{}}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, func() *apiv1.CreateKeyResponse { return nil }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.CreateKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			want := tt.wantFn()
			if !reflect.DeepEqual(got, want) {
				t.Errorf("YubiKey.CreateKey() = %v, want %v", got, want)
			}
		})
	}
}

func TestYubiKey_CreateKey_policies(t *testing.T) {
	yk := newStubPivKey(t, ECDSA)

	type fields struct {
		yk            pivKey
		pin           string
		managementKey []byte
	}
	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		wantSlot        piv.Slot
		wantPinPolicy   piv.PINPolicy
		wantTouchPolicy piv.TouchPolicy
		wantFn          func() *apiv1.CreateKeyResponse
		wantErr         bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, slotMapping["82"], piv.PINPolicyAlways, piv.TouchPolicyNever, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok PINPolicyNever", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			PINPolicy:          apiv1.PINPolicyNever,
		}}, slotMapping["82"], piv.PINPolicyNever, piv.TouchPolicyNever, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok PINPolicyOnce", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			PINPolicy:          apiv1.PINPolicyOnce,
		}}, slotMapping["82"], piv.PINPolicyOnce, piv.TouchPolicyNever, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok PINPolicyAlways", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			PINPolicy:          apiv1.PINPolicyAlways,
		}}, slotMapping["82"], piv.PINPolicyAlways, piv.TouchPolicyNever, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok TouchPolicyNever", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			TouchPolicy:        apiv1.TouchPolicyNever,
		}}, slotMapping["82"], piv.PINPolicyAlways, piv.TouchPolicyNever, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok TouchPolicyAlways", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			TouchPolicy:        apiv1.TouchPolicyAlways,
		}}, slotMapping["82"], piv.PINPolicyAlways, piv.TouchPolicyAlways, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok TouchPolicyCached", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			TouchPolicy:        apiv1.TouchPolicyCached,
		}}, slotMapping["82"], piv.PINPolicyAlways, piv.TouchPolicyCached, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok both policies", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			PINPolicy:          apiv1.PINPolicyNever,
			TouchPolicy:        apiv1.TouchPolicyAlways,
		}}, slotMapping["82"], piv.PINPolicyNever, piv.TouchPolicyAlways, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.CreateKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if v := yk.keyOptionsMap[tt.wantSlot].PINPolicy; !reflect.DeepEqual(v, tt.wantPinPolicy) {
				t.Errorf("YubiKey.CreateKey() PINPolicy = %v, want %v", v, tt.wantPinPolicy)
			}
			if v := yk.keyOptionsMap[tt.wantSlot].TouchPolicy; !reflect.DeepEqual(v, tt.wantTouchPolicy) {
				t.Errorf("YubiKey.CreateKey() TouchPolicy = %v, want %v", v, tt.wantTouchPolicy)
			}
			want := tt.wantFn()
			if !reflect.DeepEqual(got, want) {
				t.Errorf("YubiKey.CreateKey() = %v, want %v", got, want)
			}

		})
	}
}

func TestYubiKey_CreateSigner(t *testing.T) {
	yk := newStubPivKey(t, ECDSA)

	ykFail := newStubPivKey(t, ECDSA)
	ykFail.signerMap[piv.SlotSignature] = "not-a-signer"

	type fields struct {
		yk            pivKey
		pin           string
		managementKey []byte
	}
	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=9c",
		}}, &syncSigner{Signer: yk.signerMap[piv.SlotSignature].(crypto.Signer)}, false},
		{"ok with pin", fields{yk, "", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=9c?pin-value=123456",
		}}, &syncSigner{Signer: yk.signerMap[piv.SlotSignature].(crypto.Signer)}, false},
		{"fail getSlot", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=%%FF",
		}}, nil, true},
		{"fail getPublicKey", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=85",
		}}, nil, true},
		{"fail privateKey", fields{yk, "654321", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=9c",
		}}, nil, true},
		{"fail signer", fields{ykFail, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=9c",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.CreateSigner(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.CreateSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("YubiKey.CreateSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubiKey_CreateDecrypter(t *testing.T) {
	yk := newStubPivKey(t, RSA)

	ykFail := newStubPivKey(t, RSA)
	ykFail.signerMap[piv.SlotSignature] = "not-a-decrypter"

	// interface conversion: *ecdsa.PrivateKey is not crypto.Decrypter: missing method Decrypt
	ykFailEC := newStubPivKey(t, ECDSA)

	type fields struct {
		yk            pivKey
		pin           string
		managementKey []byte
	}
	type args struct {
		req *apiv1.CreateDecrypterRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.Decrypter
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateDecrypterRequest{
			DecryptionKey: "yubikey:slot-id=9c",
		}}, &syncDecrypter{Decrypter: yk.signerMap[piv.SlotSignature].(crypto.Decrypter)}, false},
		{"ok with pin", fields{yk, "", piv.DefaultManagementKey}, args{&apiv1.CreateDecrypterRequest{
			DecryptionKey: "yubikey:slot-id=9c?pin-value=123456",
		}}, &syncDecrypter{Decrypter: yk.signerMap[piv.SlotSignature].(crypto.Decrypter)}, false},
		{"fail getSlot", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateDecrypterRequest{
			DecryptionKey: "yubikey:slot-id=%%FF",
		}}, nil, true},
		{"fail getPublicKey", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateDecrypterRequest{
			DecryptionKey: "yubikey:slot-id=85",
		}}, nil, true},
		{"fail privateKey", fields{yk, "654321", piv.DefaultManagementKey}, args{&apiv1.CreateDecrypterRequest{
			DecryptionKey: "yubikey:slot-id=9c",
		}}, nil, true},
		{"fail signer", fields{ykFail, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateDecrypterRequest{
			DecryptionKey: "yubikey:slot-id=9c",
		}}, nil, true},
		{"fail no decrypt support", fields{ykFailEC, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateDecrypterRequest{
			DecryptionKey: "yubikey:slot-id=9c",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.CreateDecrypter(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.CreateDecrypter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("YubiKey.CreateDecrypter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubiKey_CreateAttestation(t *testing.T) {
	yk := newStubPivKey(t, ECDSA)

	ykA1 := newStubPivKey(t, ECDSA)
	ykA1.attestCA.Intermediate.Issuer.CommonName = "Yubico PIV Attestation A 1"

	ykB1 := newStubPivKey(t, ECDSA)
	ykB1.attestCA.Intermediate.Issuer.CommonName = "Yubico PIV Attestation B 1"

	ykFail := newStubPivKey(t, ECDSA)
	delete(ykFail.certMap, slotAttestation)

	a1Certs, err := pemutil.ParseCertificateBundle([]byte(yubicoPIVAttestationA1))
	require.NoError(t, err)
	b1Certs, err := pemutil.ParseCertificateBundle([]byte(yubicoPIVAttestationB1))
	require.NoError(t, err)

	type fields struct {
		yk            pivKey
		pin           string
		managementKey []byte
	}
	type args struct {
		req *apiv1.CreateAttestationRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.CreateAttestationResponse
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateAttestationRequest{
			Name: "yubikey:slot-id=9a",
		}}, &apiv1.CreateAttestationResponse{
			Certificate:         yk.attestMap[piv.SlotAuthentication],
			CertificateChain:    []*x509.Certificate{yk.attestMap[piv.SlotAuthentication], yk.attestCA.Intermediate},
			PublicKey:           yk.attestMap[piv.SlotAuthentication].PublicKey,
			PermanentIdentifier: "112233",
		}, false},
		{"ok A1", fields{ykA1, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateAttestationRequest{
			Name: "yubikey:slot-id=9a",
		}}, &apiv1.CreateAttestationResponse{
			Certificate: ykA1.attestMap[piv.SlotAuthentication],
			CertificateChain: []*x509.Certificate{
				ykA1.attestMap[piv.SlotAuthentication], ykA1.attestCA.Intermediate,
				a1Certs[0], a1Certs[1],
			},
			PublicKey:           ykA1.attestMap[piv.SlotAuthentication].PublicKey,
			PermanentIdentifier: "112233",
		}, false},
		{"ok B1", fields{ykB1, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateAttestationRequest{
			Name: "yubikey:slot-id=9a",
		}}, &apiv1.CreateAttestationResponse{
			Certificate: ykB1.attestMap[piv.SlotAuthentication],
			CertificateChain: []*x509.Certificate{
				ykB1.attestMap[piv.SlotAuthentication], ykB1.attestCA.Intermediate,
				b1Certs[0], b1Certs[1],
			},
			PublicKey:           ykB1.attestMap[piv.SlotAuthentication].PublicKey,
			PermanentIdentifier: "112233",
		}, false},
		{"fail getSlot", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateAttestationRequest{
			Name: "yubikey://:slot-id=9a",
		}}, nil, true},
		{"fail attest", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateAttestationRequest{
			Name: "yubikey:slot-id=85",
		}}, nil, true},
		{"fail certificate", fields{ykFail, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateAttestationRequest{
			Name: "yubikey:slot-id=9a",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.CreateAttestation(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.CreateAttestation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("YubiKey.CreateAttestation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubiKey_Serial(t *testing.T) {
	yk1 := newStubPivKey(t, RSA)
	yk2 := newStubPivKey(t, RSA)
	yk2.serialErr = errors.New("some error")

	tests := []struct {
		name    string
		yk      pivKey
		want    string
		wantErr bool
	}{
		{"ok", yk1, "112233", false},
		{"fail", yk2, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk: tt.yk,
			}
			got, err := k.Serial()
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.Serial() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("YubiKey.Serial() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubiKey_Close(t *testing.T) {
	yk1 := newStubPivKey(t, ECDSA)
	yk2 := newStubPivKey(t, RSA)
	yk2.closeErr = errors.New("some error")

	type fields struct {
		yk            pivKey
		pin           string
		managementKey []byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{yk1, "123456", piv.DefaultManagementKey}, false},
		{"fail", fields{yk2, "123456", piv.DefaultManagementKey}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			if err := k.Close(); (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getAttestedSerial(t *testing.T) {
	serialNumber, err := asn1.Marshal(112233)
	if err != nil {
		t.Fatal(err)
	}
	printableSerialNumber, err := asn1.Marshal("112233")
	if err != nil {
		t.Fatal(err)
	}

	yk := newStubPivKey(t, RSA)
	okCert := yk.attestMap[piv.SlotAuthentication]
	printableCert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "attested certificate"},
		PublicKey: okCert.PublicKey,
		Extensions: []pkix.Extension{
			{Id: oidYubicoSerialNumber, Value: printableSerialNumber},
		},
	}
	restCert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "attested certificate"},
		PublicKey: okCert.PublicKey,
		Extensions: []pkix.Extension{
			{Id: oidYubicoSerialNumber, Value: append(serialNumber, 0)},
		},
	}
	missingCert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "attested certificate"},
		PublicKey: okCert.PublicKey,
	}

	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"ok", args{okCert}, "112233"},
		{"fail printable", args{printableCert}, ""},
		{"fail rest", args{restCert}, ""},
		{"fail missing", args{missingCert}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAttestedSerial(tt.args.cert); got != tt.want {
				t.Errorf("getAttestedSerial() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getSignatureAlgorithm(t *testing.T) {
	fake := apiv1.SignatureAlgorithm(1000)
	t.Cleanup(func() {
		delete(signatureAlgorithmMapping, fake)
	})
	signatureAlgorithmMapping[fake] = "fake"

	type args struct {
		alg  apiv1.SignatureAlgorithm
		bits int
	}
	tests := []struct {
		name    string
		args    args
		want    piv.Algorithm
		wantErr bool
	}{
		{"default", args{apiv1.UnspecifiedSignAlgorithm, 0}, piv.AlgorithmEC256, false},
		{"SHA256WithRSA", args{apiv1.SHA256WithRSA, 0}, piv.AlgorithmRSA2048, false},
		{"SHA512WithRSA", args{apiv1.SHA512WithRSA, 0}, piv.AlgorithmRSA2048, false},
		{"SHA256WithRSAPSS", args{apiv1.SHA256WithRSAPSS, 0}, piv.AlgorithmRSA2048, false},
		{"SHA512WithRSAPSS", args{apiv1.SHA512WithRSAPSS, 0}, piv.AlgorithmRSA2048, false},
		{"ECDSAWithSHA256", args{apiv1.ECDSAWithSHA256, 0}, piv.AlgorithmEC256, false},
		{"ECDSAWithSHA384", args{apiv1.ECDSAWithSHA384, 0}, piv.AlgorithmEC384, false},
		{"PureEd25519", args{apiv1.PureEd25519, 0}, piv.AlgorithmEd25519, false},
		{"SHA256WithRSA 1024", args{apiv1.SHA256WithRSA, 1024}, piv.AlgorithmRSA1024, false},
		{"SHA512WithRSA 1024", args{apiv1.SHA512WithRSA, 1024}, piv.AlgorithmRSA1024, false},
		{"SHA256WithRSAPSS 1024", args{apiv1.SHA256WithRSAPSS, 1024}, piv.AlgorithmRSA1024, false},
		{"SHA512WithRSAPSS 1024", args{apiv1.SHA512WithRSAPSS, 1024}, piv.AlgorithmRSA1024, false},
		{"SHA256WithRSA 2048", args{apiv1.SHA256WithRSA, 2048}, piv.AlgorithmRSA2048, false},
		{"SHA512WithRSA 2048", args{apiv1.SHA512WithRSA, 2048}, piv.AlgorithmRSA2048, false},
		{"SHA256WithRSAPSS 2048", args{apiv1.SHA256WithRSAPSS, 2048}, piv.AlgorithmRSA2048, false},
		{"SHA512WithRSAPSS 2048", args{apiv1.SHA512WithRSAPSS, 2048}, piv.AlgorithmRSA2048, false},
		{"SHA256WithRSA 3072", args{apiv1.SHA256WithRSA, 3072}, piv.AlgorithmRSA3072, false},
		{"SHA512WithRSA 3072", args{apiv1.SHA512WithRSA, 3072}, piv.AlgorithmRSA3072, false},
		{"SHA256WithRSAPSS 3072", args{apiv1.SHA256WithRSAPSS, 3072}, piv.AlgorithmRSA3072, false},
		{"SHA512WithRSAPSS 3072", args{apiv1.SHA512WithRSAPSS, 3072}, piv.AlgorithmRSA3072, false},
		{"SHA256WithRSA 4096", args{apiv1.SHA256WithRSA, 4096}, piv.AlgorithmRSA4096, false},
		{"SHA512WithRSA 4096", args{apiv1.SHA512WithRSA, 4096}, piv.AlgorithmRSA4096, false},
		{"SHA256WithRSAPSS 4096", args{apiv1.SHA256WithRSAPSS, 4096}, piv.AlgorithmRSA4096, false},
		{"SHA512WithRSAPSS 4096", args{apiv1.SHA512WithRSAPSS, 4096}, piv.AlgorithmRSA4096, false},
		{"fail 512", args{apiv1.SHA256WithRSA, 512}, 0, true},
		{"fail unknown", args{apiv1.SignatureAlgorithm(100), 0}, 0, true},
		{"fail default case", args{apiv1.SignatureAlgorithm(1000), 0}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getSignatureAlgorithm(tt.args.alg, tt.args.bits)
			if (err != nil) != tt.wantErr {
				t.Errorf("getSignatureAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getSignatureAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_syncSigner_Sign(t *testing.T) {
	s, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := &syncSigner{Signer: s}

	sum := sha256.Sum256([]byte("the-data"))
	sig, err := signer.Sign(rand.Reader, sum[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(&s.PublicKey, sum[:], sig))
}

func Test_syncDecrypter_Decrypt(t *testing.T) {
	d, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	require.NoError(t, err)

	label := []byte("label")
	data := []byte("the-data")

	msg, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, &d.PublicKey, data, label)
	require.NoError(t, err)

	decrypter := &syncDecrypter{Decrypter: d}
	plain, err := decrypter.Decrypt(rand.Reader, msg, &rsa.OAEPOptions{
		Hash:  crypto.SHA256,
		Label: label,
	})
	assert.NoError(t, err)
	assert.Equal(t, data, plain)
}

func TestYubicoNewRoots(t *testing.T) {
	const rootPEM = `-----BEGIN CERTIFICATE-----
MIIDPjCCAiagAwIBAgIUXzeiEDJEOTt14F5n0o6Zf/bBwiUwDQYJKoZIhvcNAQEN
BQAwJDEiMCAGA1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTAgFw0yNDEy
MDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowJDEiMCAGA1UEAwwZWXViaWNvIEF0
dGVzdGF0aW9uIFJvb3QgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMZ6/TxM8rIT+EaoPvG81ontMOo/2mQ2RBwJHS0QZcxVaNXvl12LUhBZ5LmiBScI
Zd1Rnx1od585h+/dhK7hEm7JAALkKKts1fO53KGNLZujz5h3wGncr4hyKF0G74b/
U3K9hE5mGND6zqYchCRAHfrYMYRDF4YL0X4D5nGdxvppAy6nkEmtWmMnwO3i0TAu
csrbE485HvGM4r0VpgVdJpvgQjiTJCTIq+D35hwtT8QDIv+nGvpcyi5wcIfCkzyC
imJukhYy6KoqNMKQEdpNiSOvWyDMTMt1bwCvEzpw91u+msUt4rj0efnO9s0ZOwdw
MRDnH4xgUl5ZLwrrPkfC1/0CAwEAAaNmMGQwHQYDVR0OBBYEFNLu71oijTptXCOX
PfKF1SbxJXuSMB8GA1UdIwQYMBaAFNLu71oijTptXCOXPfKF1SbxJXuSMBIGA1Ud
EwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBDQUAA4IB
AQC3IW/sgB9pZ8apJNjxuGoX+FkILks0wMNrdXL/coUvsrhzsvl6mePMrbGJByJ1
XnquB5sgcRENFxdQFma3mio8Upf1owM1ZreXrJ0mADG2BplqbJnxiyYa+R11reIF
TWeIhMNcZKsDZrFAyPuFjCWSQvJmNWe9mFRYFgNhXJKkXIb5H1XgEDlwiedYRM7V
olBNlld6pRFKlX8ust6OTMOeADl2xNF0m1LThSdeuXvDyC1g9+ILfz3S6OIYgc3i
roRcFD354g7rKfu67qFAw9gC4yi0xBTPrY95rh4/HqaUYCA/L8ldRk6H7Xk35D+W
Vpmq2Sh/xT5HiFuhf4wJb0bK
-----END CERTIFICATE-----`

	root, err := pemutil.ParseCertificate([]byte(rootPEM))
	require.NoError(t, err)

	a1Certs, err := pemutil.ParseCertificateBundle([]byte(yubicoPIVAttestationA1))
	require.NoError(t, err)
	require.Len(t, a1Certs, 2)

	b1Certs, err := pemutil.ParseCertificateBundle([]byte(yubicoPIVAttestationB1))
	require.NoError(t, err)
	require.Len(t, b1Certs, 2)

	assert.Equal(t, "Yubico PIV Attestation A 1", a1Certs[0].Subject.CommonName)
	assert.Equal(t, "Yubico Attestation Intermediate A 1", a1Certs[1].Subject.CommonName)

	assert.Equal(t, "Yubico PIV Attestation B 1", b1Certs[0].Subject.CommonName)
	assert.Equal(t, "Yubico Attestation Intermediate B 1", b1Certs[1].Subject.CommonName)

	assert.True(t, a1Certs[0].BasicConstraintsValid)
	assert.True(t, a1Certs[0].IsCA)
	assert.True(t, a1Certs[0].MaxPathLen == 1)
	assert.True(t, a1Certs[1].BasicConstraintsValid)
	assert.True(t, a1Certs[1].IsCA)
	assert.True(t, a1Certs[1].MaxPathLen == 2)

	assert.True(t, b1Certs[0].BasicConstraintsValid)
	assert.True(t, b1Certs[0].IsCA)
	assert.True(t, b1Certs[0].MaxPathLen == 1)
	assert.True(t, b1Certs[1].BasicConstraintsValid)
	assert.True(t, b1Certs[1].IsCA)
	assert.True(t, b1Certs[1].MaxPathLen == 2)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)
	for _, chain := range [][]*x509.Certificate{a1Certs, b1Certs} {
		intPool := x509.NewCertPool()
		intPool.AddCert(chain[1])

		_, err := chain[0].Verify(x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: intPool,
		})
		assert.NoError(t, err)
	}

}
