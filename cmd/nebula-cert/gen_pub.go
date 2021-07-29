package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/slackhq/nebula/cert"
)

type genPubFlags struct {
	set        *flag.FlagSet
	inKeyPath  *string
	outPubPath *string
}

func newGenPubFlags() *genPubFlags {
	pf := genPubFlags{set: flag.NewFlagSet("gen-pub", flag.ContinueOnError)}
	pf.set.Usage = func() {}
	pf.inKeyPath = pf.set.String("in-key", "", "Required: path to read the private key from")
	pf.outPubPath = pf.set.String("out-pub", "", "Optional: path to write the public key to")
	return &pf
}

func genPub(args []string, out io.Writer, errOut io.Writer) error {
	pf := newGenPubFlags()
	err := pf.set.Parse(args)
	if err != nil {
		return err
	}
	if err := mustFlagString("in-key", pf.inKeyPath); err != nil {
		return err
	}

	rawPriv, err := ioutil.ReadFile(*pf.inKeyPath)
	if err != nil {
		return fmt.Errorf("error while reading in-priv: %s", err)
	}
	priv, _, err := cert.UnmarshalX25519PrivateKey(rawPriv)
	if err != nil {
		return fmt.Errorf("error while parsing in-priv: %s", err)
	}
	pub := x25519PubKey(priv)

	if *pf.outPubPath != "" {
		err = ioutil.WriteFile(*pf.outPubPath, cert.MarshalX25519PublicKey(pub), 0600)
		if err != nil {
			return fmt.Errorf("error while writing out-crt: %s", err)
		}

	} else {
		fmt.Printf("%s", cert.MarshalX25519PublicKey(pub))
	}
	return nil
}

func genPubSummary() string {
	return "gen-pub <flags>: prints the public key given the private key"
}

func genPubHelp(out io.Writer) {
	pf := newGenPubFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + genPubSummary() + "\n"))
	pf.set.SetOutput(out)
	pf.set.PrintDefaults()
}
