package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/slackhq/nebula/cert"
)

type keygenFlags struct {
	set        *flag.FlagSet
	outKeyPath *string
	outPubPath *string

	curve *string
}

func newKeygenFlags() *keygenFlags {
	cf := keygenFlags{set: flag.NewFlagSet("keygen", flag.ContinueOnError)}
	cf.set.Usage = func() {}
	cf.outPubPath = cf.set.String("out-pub", "", "Required: path to write the public key to")
	cf.outKeyPath = cf.set.String("out-key", "", "Required: path to write the private key to")
	cf.curve = cf.set.String("curve", "25519", "ECDH Curve (25519, P256)")
	return &cf
}

func keygen(args []string, out io.Writer, errOut io.Writer) error {
	cf := newKeygenFlags()
	err := cf.set.Parse(args)
	if err != nil {
		return err
	}

	if err := mustFlagString("out-key", cf.outKeyPath); err != nil {
		return err
	}
	if err := mustFlagString("out-pub", cf.outPubPath); err != nil {
		return err
	}

	var pub, rawPriv []byte
	var curve cert.Curve
	switch *cf.curve {
	case "25519", "X25519", "Curve25519", "CURVE25519":
		pub, rawPriv = x25519Keypair()
		curve = cert.Curve_CURVE25519
	case "P256":
		pub, rawPriv = p256Keypair()
		curve = cert.Curve_P256
	default:
		return fmt.Errorf("invalid curve: %s", *cf.curve)
	}

	err = os.WriteFile(*cf.outKeyPath, cert.MarshalPrivateKey(curve, rawPriv), 0600)
	if err != nil {
		return fmt.Errorf("error while writing out-key: %s", err)
	}

	err = os.WriteFile(*cf.outPubPath, cert.MarshalPublicKey(curve, pub), 0600)
	if err != nil {
		return fmt.Errorf("error while writing out-pub: %s", err)
	}

	return nil
}

func keygenSummary() string {
	return "keygen <flags>: create a public/private key pair. the public key can be passed to `nebula-cert sign`"
}

func keygenHelp(out io.Writer) {
	cf := newKeygenFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + keygenSummary() + "\n"))
	cf.set.SetOutput(out)
	cf.set.PrintDefaults()
}
