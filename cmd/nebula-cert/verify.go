package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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
	vf.certPath = vf.set.String("crt", "", "Required: path to a file containing one or more certificates")
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

	var claims ioClaims
	if err := reserveInputs(&claims,
		"ca", *vf.caPath,
		"crt", *vf.certPath,
	); err != nil {
		return err
	}

	caReader, err := openInput("ca", *vf.caPath, &claims)
	if err != nil {
		return fmt.Errorf("error while reading ca: %w", err)
	}
	defer caReader.Close()

	caPool, err := cert.NewCAPoolFromPEMReader(caReader)
	if caPool == nil {
		return fmt.Errorf("error while adding ca cert to pool: %w", err)
	}
	for _, e := range cert.SkippedCertificates(err) {
		fmt.Fprintf(errOut, "skipping ca: %s\n", e)
	}
	if len(caPool.CAs) == 0 {
		return errors.New("no valid CA certificates present")
	}

	rawCert, err := readInput("crt", *vf.certPath, &claims)
	if err != nil {
		return fmt.Errorf("unable to read crt: %w", err)
	}
	var errs []error
	var checked int
	scanner := cert.NewPEMScanner(bytes.NewReader(rawCert))
	for i := 1; scanner.Scan(); i++ {
		c, _, err := cert.UnmarshalCertificateFromPEM(scanner.Bytes())
		if errors.Is(err, cert.ErrUnknownVersion) {
			fmt.Fprintf(errOut, "skipping crt: certificate %d: %s\n", i, err)
			continue
		} else if err != nil {
			return fmt.Errorf("error while parsing crt: %w", err)
		}
		if err := cert.CheckKnownCurve(c); err != nil {
			fmt.Fprintf(errOut, "skipping crt: certificate %d: %s\n", i, err)
			continue
		}
		checked++
		_, err = caPool.VerifyCertificate(time.Now(), c)
		if err != nil {
			switch {
			case errors.Is(err, cert.ErrCaNotFound):
				errs = append(errs, fmt.Errorf("error while verifying certificate v%d %s with issuer %s: %w", c.Version(), cert.QuoteName(c.Name()), c.Issuer(), err))
			default:
				errs = append(errs, fmt.Errorf("error while verifying certificate %+v: %w", c, err))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error while parsing crt: %w: %w", cert.ErrInvalidPEMBlock, err)
	}

	if checked == 0 {
		return errors.New("no valid certificates found in crt")
	}

	return errors.Join(errs...)
}

func verifySummary() string {
	return "verify <flags>: verifies a certificate isn't expired and was signed by a trusted authority."
}

func verifyHelp(out io.Writer) {
	vf := newVerifyFlags()
	_, _ = out.Write([]byte("Usage of " + os.Args[0] + " " + verifySummary() + "\n"))
	_, _ = out.Write([]byte(stdioHelpText))
	vf.set.SetOutput(out)
	vf.set.PrintDefaults()
}
