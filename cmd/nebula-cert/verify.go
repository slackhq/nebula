package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"
)

type verifyFlags struct {
	set      *flag.FlagSet
	caPath   *string
	certPath *string
}

func newVerifyFlags() *verifyFlags {
	vf := verifyFlags{set: flag.NewFlagSet("verify", flag.ContinueOnError)}
	vf.set.Usage = func() {}
	vf.caPath = vf.set.String("ca", "", "Required: path to a file containing one or more ca certificates")
	vf.certPath = vf.set.String("crt", "", "Required: path to a file containing a single certificate")
	return &vf
}

func verify(args []string, out io.Writer, errOut io.Writer) error {
	vf := newVerifyFlags()
	err := vf.set.Parse(args)
	if err != nil {
		return err
	}

	if err := mustFlagString("ca", vf.caPath); err != nil {
		return err
	}
	if err := mustFlagString("crt", vf.certPath); err != nil {
		return err
	}

	rawCACert, err := os.ReadFile(*vf.caPath)
	if err != nil {
		return fmt.Errorf("error while reading ca: %s", err)
	}

	caPool := cert.NewCAPool()
	for {
		rawCACert, err = caPool.AddCAFromPEM(rawCACert)
		if err != nil {
			return fmt.Errorf("error while adding ca cert to pool: %s", err)
		}

		if rawCACert == nil || len(rawCACert) == 0 || strings.TrimSpace(string(rawCACert)) == "" {
			break
		}
	}

	rawCert, err := os.ReadFile(*vf.certPath)
	if err != nil {
		return fmt.Errorf("unable to read crt; %s", err)
	}

	c, _, err := cert.UnmarshalCertificateFromPEM(rawCert)
	if err != nil {
		return fmt.Errorf("error while parsing crt: %s", err)
	}

	_, err = caPool.VerifyCertificate(time.Now(), c)
	if err != nil {
		return err
	}

	return nil
}

func verifySummary() string {
	return "verify <flags>: verifies a certificate isn't expired and was signed by a trusted authority."
}

func verifyHelp(out io.Writer) {
	vf := newVerifyFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + verifySummary() + "\n"))
	vf.set.SetOutput(out)
	vf.set.PrintDefaults()
}
