package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/skip2/go-qrcode"
	"github.com/slackhq/nebula/cert"
)

type printFlags struct {
	set       *flag.FlagSet
	json      *bool
	outQRPath *string
	path      *string
}

func newPrintFlags() *printFlags {
	pf := printFlags{set: flag.NewFlagSet("print", flag.ContinueOnError)}
	pf.set.Usage = func() {}
	pf.json = pf.set.Bool("json", false, "Optional: outputs certificates in json format")
	pf.outQRPath = pf.set.String("out-qr", "", "Optional: output a qr code image (png) of the certificate")
	pf.path = pf.set.String("path", "", "Required: path to the certificate")

	return &pf
}

func printCert(args []string, out io.Writer, errOut io.Writer) error {
	pf := newPrintFlags()
	err := pf.set.Parse(args)
	if err != nil {
		return err
	}

	if err := mustFlagString("path", pf.path); err != nil {
		return err
	}

	rawCert, err := os.ReadFile(*pf.path)
	if err != nil {
		return fmt.Errorf("unable to read cert; %s", err)
	}

	var c cert.Certificate
	var qrBytes []byte
	part := 0

	var jsonCerts []cert.Certificate

	for {
		c, rawCert, err = cert.UnmarshalCertificateFromPEM(rawCert)
		if err != nil {
			return fmt.Errorf("error while unmarshaling cert: %s", err)
		}

		if *pf.json {
			jsonCerts = append(jsonCerts, c)
		} else {
			_, _ = out.Write([]byte(c.String()))
			_, _ = out.Write([]byte("\n"))
		}

		if *pf.outQRPath != "" {
			b, err := c.MarshalPEM()
			if err != nil {
				return fmt.Errorf("error while marshalling cert to PEM: %s", err)
			}
			qrBytes = append(qrBytes, b...)
		}

		if rawCert == nil || len(rawCert) == 0 || strings.TrimSpace(string(rawCert)) == "" {
			break
		}

		part++
	}

	if *pf.json {
		b, _ := json.Marshal(jsonCerts)
		_, _ = out.Write(b)
		_, _ = out.Write([]byte("\n"))
	}

	if *pf.outQRPath != "" {
		b, err := qrcode.Encode(string(qrBytes), qrcode.Medium, -5)
		if err != nil {
			return fmt.Errorf("error while generating qr code: %s", err)
		}

		err = os.WriteFile(*pf.outQRPath, b, 0600)
		if err != nil {
			return fmt.Errorf("error while writing out-qr: %s", err)
		}
	}

	return nil
}

func printSummary() string {
	return "print <flags>: prints details about a certificate"
}

func printHelp(out io.Writer) {
	pf := newPrintFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + printSummary() + "\n"))
	pf.set.SetOutput(out)
	pf.set.PrintDefaults()
}
