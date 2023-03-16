package manufacturer

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var (
	manufacturerByASCII map[string]string
	validChars          *regexp.Regexp
)

// ID models a TPM Manufacturer (or Vendor) ID.
type ID uint32

func (id ID) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(id), 10))
}

// GetEncodings returns the ASCII and hexadecimal representations
// of the manufacturer ID.
func GetEncodings(id ID) (ascii, hexa string) {
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], uint32(id))
	ascii = string(b[:])
	ascii = validChars.ReplaceAllString(ascii, "") // NOTE: strips \x00 characters (a.o)
	hexa = strings.ToUpper(hex.EncodeToString(b[:]))

	return
}

// GetNameByASCII returns the manufacturer name based on its
// ASCII identifier.
func GetNameByASCII(ascii string) string {
	if name, ok := manufacturerByASCII[ascii]; ok {
		return name
	}
	return "unknown"
}

func init() {
	// manufacturerByASCII contains a mapping of TPM manufacturer
	// ASCII names to full manufacturer names. It is mainly based on the data
	// provided on https://trustedcomputinggroup.org/resource/vendor-id-registry/,
	// e.g. https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-VendorIDRegistry-v1p06-r0p91-pub.pdf
	// Some additional known manufacturers are provided too.
	manufacturerByASCII = map[string]string{
		// 4.1 Product Implementations
		"AMD":  "AMD",
		"ATML": "Atmel",
		"BRCM": "Broadcom",
		"CSCO": "Cisco",
		"FLYS": "Flyslice Technologies",
		"ROCC": "Fuzhou Rockchip",
		"GOOG": "Google",
		"HPE":  "HPE",
		"HISI": "Huawei",
		"IBM":  "IBM",
		"IFX":  "Infineon",
		"INTC": "Intel",
		"LEN":  "Lenovo",
		"MSFT": "Microsoft",
		"NSM":  "National Semiconductor",
		"NTZ":  "Nationz",
		"NTC":  "Nuvoton Technology",
		"QCOM": "Qualcomm",
		"SMSN": "Samsung",
		"SNS":  "Sinosun",
		"SMSC": "SMSC",
		"STM":  "ST Microelectronics",
		"TXN":  "Texas Instruments",
		"WEC":  "Winbond",

		// 4.2 Simulator and Testing Implementations
		"SIM0": "Simulator 0",
		"SIM1": "Simulator 1",
		"SIM2": "Simulator 2",
		"SIM3": "Simulator 3",
		"SIM4": "Simulator 4",
		"SIM5": "Simulator 5",
		"SIM6": "Simulator 6",
		"SIM7": "Simulator 7",
		"TST0": "Test 0",
		"TST1": "Test 1",
		"TST2": "Test 2",
		"TST3": "Test 3",
		"TST4": "Test 4",
		"TST5": "Test 5",
		"TST6": "Test 6",
		"TST7": "Test 7",

		// Others
		"PRLS": "Parallels Desktop",
		"VMW":  "VMWare",
	}

	validChars = regexp.MustCompile(`[^a-zA-Z0-9 ]+`)
}
