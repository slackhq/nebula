package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/slackhq/nebula/cert"
)

type keygenFlags struct {
	set        *flag.FlagSet
	outKeyPath *string
	outPubPath *string
}

func newKeygenFlags() *keygenFlags {
	cf := keygenFlags{set: flag.NewFlagSet("keygen", flag.ContinueOnError)}
	cf.set.Usage = func() {}
	cf.outPubPath = cf.set.String("out-pub", "", "Required: path to write the public key to")
	cf.outKeyPath = cf.set.String("out-key", "", "Required: path to write the private key to")
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

	pub, rawPriv := x25519Keypair()

	err = ioutil.WriteFile(*cf.outKeyPath, cert.MarshalX25519PrivateKey(rawPriv), 0600)
	if err != nil {
		return fmt.Errorf("error while writing out-key: %s", err)
	}

	err = ioutil.WriteFile(*cf.outPubPath, cert.MarshalX25519PublicKey(pub), 0600)
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
