package algorithm

import (
	"encoding/json"
	"slices"

	"github.com/google/go-tpm/legacy/tpm2"
)

var (
	algs map[tpm2.Algorithm]string
)

type Algorithm tpm2.Algorithm

func (a Algorithm) String() string {
	return algs[tpm2.Algorithm(int(a))]
}

func (a Algorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

type AlgorithmSlice struct {
	algs []Algorithm
}

func (s *AlgorithmSlice) Supports(algs ...Algorithm) bool {
	if len(algs) == 0 {
		return false
	}

	for _, alg := range algs {
		if !slices.Contains(s.algs, alg) {
			return false
		}
	}

	return true
}

func init() {
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
	algs = map[tpm2.Algorithm]string{
		// object types
		tpm2.AlgRSA: "RSA",
		tpm2.AlgECC: "ECC",

		// encryption algs
		tpm2.AlgRSAES: "RSAES",

		// block ciphers
		0x0003:            "3DES",
		tpm2.AlgAES:       "AES",
		0x0026:            "Camellia",
		tpm2.AlgECB:       "ECB",
		tpm2.AlgCFB:       "CFB",
		tpm2.AlgOFB:       "OFB",
		tpm2.AlgCBC:       "CBC",
		tpm2.AlgCTR:       "CTR",
		tpm2.AlgSymCipher: "Symmetric Cipher",
		0x003F:            "CMAC",

		// other ciphers
		tpm2.AlgXOR:  "XOR",
		tpm2.AlgNull: "Null Cipher",

		// hash algs
		tpm2.AlgSHA1:      "SHA-1",
		tpm2.AlgHMAC:      "HMAC",
		0x0007:            "MGF1",
		tpm2.AlgKeyedHash: "Keyed Hash",
		0x0012:            "SM3-256",
		tpm2.AlgSHA256:    "SHA-256",
		tpm2.AlgSHA384:    "SHA-384",
		tpm2.AlgSHA512:    "SHA-512",
		tpm2.AlgSHA3_256:  "SHA3-256",
		tpm2.AlgSHA3_384:  "SHA3-384",
		tpm2.AlgSHA3_512:  "SHA3-512",

		// signature algs
		0x0013:         "SM4",
		tpm2.AlgRSASSA: "RSA-SSA",
		tpm2.AlgRSAPSS: "RSA-PSS",
		tpm2.AlgECDSA:  "ECDSA",
		tpm2.AlgECDAA:  "ECDAA",
		0x001C:         "EC-Schnorr",

		// encryption schemes
		tpm2.AlgOAEP: "OAEP",
		tpm2.AlgECDH: "ECDH",

		// key derivation
		0x0020:       "KDF1",
		0x0022:       "KDF1",
		tpm2.AlgKDF2: "KDF2",
	}
}
