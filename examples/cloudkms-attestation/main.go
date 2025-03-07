package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/cloudkms"
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "%s [options] <resource>\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var certs, attributes, content, help bool
	flag.BoolVar(&certs, "certs", false, "Print the attestation certificates")
	flag.BoolVar(&attributes, "attributes", false, "Print the attestation attributes")
	flag.BoolVar(&content, "content", false, "Print the attestation file")
	flag.BoolVar(&help, "help", false, "Print the program usage")
	flag.Parse()

	switch {
	case help:
		usage()
		os.Exit(0)
	case len(flag.Args()) != 1:
		usage()
		os.Exit(1)
	case certs && attributes, certs && content, attributes && content:
		fmt.Fprintln(flag.CommandLine.Output(), "flag --certs, --attributes, and --content are mutually exclusive")
		os.Exit(1)
	}

	km, err := cloudkms.New(context.Background(), apiv1.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}

	att, err := km.VerifyAttestation(context.Background(), flag.Arg(0))
	_ = km.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(3)
	}

	if certs {
		fmt.Println(strings.TrimSpace(att.CertChain.ManufacturerRoot))
		fmt.Println(strings.TrimSpace(att.CertChain.ManufacturerCardCert))
		fmt.Println(strings.TrimSpace(att.CertChain.ManufacturerPartitionCert))
		fmt.Println(strings.TrimSpace(att.CertChain.OwnerRoot))
		fmt.Println(strings.TrimSpace(att.CertChain.OwnerCardCert))
		fmt.Println(strings.TrimSpace(att.CertChain.OwnerPartitionCert))
		return
	}

	if attributes {
		if len(att.PublicKeyAttributes) > 0 {
			fmt.Println("Public Key Attestation")
			for _, v := range att.PublicKeyAttributes {
				fmt.Println(v.String())
			}
		}
		if len(att.PrivateKeyAttributes) > 0 {
			fmt.Println("Private Key Attestation")
			for _, v := range att.PrivateKeyAttributes {
				fmt.Println(v.String())
			}
		}
		if len(att.SymmetricKeyAttributes) > 0 {
			fmt.Println("Symmetric Key Attestation")
			for _, v := range att.SymmetricKeyAttributes {
				fmt.Println(v.String())
			}
		}
		return
	}

	if content {
		os.Stdout.Write(att.Content)
		return
	}

	fmt.Println("Attested:", att.Valid)
	fmt.Println("Generated:", att.Generated)
	fmt.Println("Extractable:", att.Extractable)
	fmt.Println("KeyType:", att.KeyType)
	fmt.Println("Algorithm:", att.Algorithm)
}
