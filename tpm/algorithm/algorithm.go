package algorithm

import (
	"encoding/json"
)

// Supported Algorithms.
const (
	AlgorithmUnknown   Algorithm = 0x0000
	AlgorithmRSA       Algorithm = 0x0001
	Algorithm3DES      Algorithm = 0x0003
	AlgorithmSHA1      Algorithm = 0x0004
	AlgorithmHMAC      Algorithm = 0x0005
	AlgorithmAES       Algorithm = 0x0006
	AlgorithmMGF1      Algorithm = 0x0007
	AlgorithmKeyedHash Algorithm = 0x0008
	AlgorithmXOR       Algorithm = 0x000A
	AlgorithmSHA256    Algorithm = 0x000B
	AlgorithmSHA384    Algorithm = 0x000C
	AlgorithmSHA512    Algorithm = 0x000D
	AlgorithmNull      Algorithm = 0x0010
	AlgorithmSM3256    Algorithm = 0x0012
	AlgorithmSM4       Algorithm = 0x0013
	AlgorithmRSASSA    Algorithm = 0x0014
	AlgorithmRSAES     Algorithm = 0x0015
	AlgorithmRSAPSS    Algorithm = 0x0016
	AlgorithmOAEP      Algorithm = 0x0017
	AlgorithmECDSA     Algorithm = 0x0018
	AlgorithmECDH      Algorithm = 0x0019
	AlgorithmECDAA     Algorithm = 0x001A
	AlgorithmECSchnorr Algorithm = 0x001C
	AlgorithmKDF1_56A  Algorithm = 0x0020
	AlgorithmKDF2      Algorithm = 0x0021
	AlgorithmKDF1_108  Algorithm = 0x0022
	AlgorithmECC       Algorithm = 0x0023
	AlgorithmSymCipher Algorithm = 0x0025
	AlgorithmCamellia  Algorithm = 0x0026
	AlgorithmSHA3_256  Algorithm = 0x0027
	AlgorithmSHA3_384  Algorithm = 0x0028
	AlgorithmSHA3_512  Algorithm = 0x0029
	AlgorithmCMAC      Algorithm = 0x003F
	AlgorithmCTR       Algorithm = 0x0040
	AlgorithmOFB       Algorithm = 0x0041
	AlgorithmCBC       Algorithm = 0x0042
	AlgorithmCFB       Algorithm = 0x0043
	AlgorithmECB       Algorithm = 0x0044
)

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
var algs = map[Algorithm]string{
	// object types
	AlgorithmRSA: "RSA",
	AlgorithmECC: "ECC",

	// encryption algs
	AlgorithmRSAES: "RSAES",

	// block ciphers
	Algorithm3DES:      "3DES",
	AlgorithmAES:       "AES",
	AlgorithmCamellia:  "Camellia",
	AlgorithmECB:       "ECB",
	AlgorithmCFB:       "CFB",
	AlgorithmOFB:       "OFB",
	AlgorithmCBC:       "CBC",
	AlgorithmCTR:       "CTR",
	AlgorithmSymCipher: "Symmetric Cipher",
	AlgorithmCMAC:      "CMAC",

	// other ciphers
	AlgorithmXOR:  "XOR",
	AlgorithmNull: "Null Cipher",

	// hash algs
	AlgorithmSHA1:      "SHA-1",
	AlgorithmHMAC:      "HMAC",
	AlgorithmMGF1:      "MGF1",
	AlgorithmKeyedHash: "Keyed Hash",
	AlgorithmSM3256:    "SM3-256",
	AlgorithmSHA256:    "SHA-256",
	AlgorithmSHA384:    "SHA-384",
	AlgorithmSHA512:    "SHA-512",
	AlgorithmSHA3_256:  "SHA3-256",
	AlgorithmSHA3_384:  "SHA3-384",
	AlgorithmSHA3_512:  "SHA3-512",

	// signature algs
	AlgorithmSM4:       "SM4",
	AlgorithmRSASSA:    "RSA-SSA",
	AlgorithmRSAPSS:    "RSA-PSS",
	AlgorithmECDSA:     "ECDSA",
	AlgorithmECDAA:     "ECDAA",
	AlgorithmECSchnorr: "EC-Schnorr",

	// encryption schemes
	AlgorithmOAEP: "OAEP",
	AlgorithmECDH: "ECDH",

	// key derivation
	AlgorithmKDF1_56A: "KDF1-SP800-56A",
	AlgorithmKDF1_108: "KDF1-SP800-108",
	AlgorithmKDF2:     "KDF2",
}

type Algorithm uint16

func (a Algorithm) String() string {
	return algs[Algorithm(int(a))]
}

func (a Algorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}
