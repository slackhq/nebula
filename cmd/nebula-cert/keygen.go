package main

import (
	"crypto/fips140"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/slackhq/nebula/pkclient"

	"github.com/slackhq/nebula/cert"
)

type keygenFlags struct {
	set        *flag.FlagSet
	outKeyPath *string
	outPubPath *string
	inKeyPath  *string
	curve      *string
	version    *uint
	pqSuite    *string
	p11url     *string
}

func newKeygenFlags() *keygenFlags {
	cf := keygenFlags{set: flag.NewFlagSet("keygen", flag.ContinueOnError)}
	cf.set.Usage = func() {}
	cf.outPubPath = cf.set.String("out-pub", "", "Required: path to write the public key to")
	cf.outKeyPath = cf.set.String("out-key", "", "Required: path to write the private key to")
	cf.curve = cf.set.String("curve", defaultCurve(), "ECDH Curve (25519, P256)")
	cf.version = cf.set.Uint("version", 0, "Optional: 3 adds a post-quantum key, for version 3 certificates")
	cf.inKeyPath = cf.set.String("in-key", "", "Optional: path to an existing private key to add a post-quantum key to, keeping the existing key. Implies -version 3")
	cf.pqSuite = pqSuiteFlag(cf.set, "Optional: post-quantum suite of a version 3 key, which must be the suite of the CA that signs it")
	cf.p11url = p11Flag(cf.set)
	return &cf
}

func keygen(args []string, out io.Writer, errOut io.Writer) error {
	cf := newKeygenFlags()
	err := cf.set.Parse(args)
	if err != nil {
		return err
	}

	isP11 := len(*cf.p11url) > 0

	if !isP11 {
		if err = mustFlagString("out-key", cf.outKeyPath); err != nil {
			return err
		}
	} else if *cf.outKeyPath != "" {
		return newHelpErrorf("cannot set -out-key with -pkcs11")
	}
	if err = mustFlagString("out-pub", cf.outPubPath); err != nil {
		return err
	}

	given := map[string]bool{}
	cf.set.Visit(func(f *flag.Flag) { given[f.Name] = true })

	version := cert.Version(*cf.version)
	if *cf.inKeyPath != "" {
		// -in-key adds a post-quantum key, which only version 3 has.
		if given["version"] && version != cert.Version3 {
			return newHelpErrorf("-in-key adds a post-quantum key, for -version %v only", cert.Version3)
		}
		version = cert.Version3
	}
	if version != 0 && version != cert.Version3 {
		return newHelpErrorf("-version must be %v, or left out for keys that work with any other version", cert.Version3)
	}
	if version == cert.Version3 && isP11 {
		return newHelpErrorf("-version 3 can not be used with -pkcs11, the post-quantum key has to be in out-key")
	}
	suite, err := parsePQSuiteFlag(cf.set, *cf.pqSuite, version == cert.Version3, "is only for -version 3")
	if err != nil {
		return err
	}

	var claims ioClaims
	if err := reserveInputs(&claims, "in-key", *cf.inKeyPath); err != nil {
		return err
	}

	var pub, rawPriv []byte
	var curve cert.Curve
	if *cf.inKeyPath != "" {
		raw, err := readInput("in-key", *cf.inKeyPath, &claims)
		if err != nil {
			return fmt.Errorf("error while reading in-key: %s", err)
		}
		key, _, err := cert.UnmarshalSplitPrivateKeyFromPEM(raw)
		if err != nil {
			return fmt.Errorf("error while parsing in-key: %s", err)
		}
		if key.PQ != nil {
			return fmt.Errorf("in-key already has a post-quantum key")
		}
		rawPriv, curve = key.Classical, key.Curve
		if given["curve"] {
			want, ok := curveFlag(*cf.curve)
			if !ok {
				return newHelpErrorf("invalid curve: %s", *cf.curve)
			}
			if want != curve {
				return newHelpErrorf("in-key is a %v key, not -curve %s", curve, *cf.curve)
			}
		}
		pub, err = publicKeyFor(curve, rawPriv)
		if err != nil {
			return fmt.Errorf("error while parsing in-key: %s", err)
		}
		if fips140.Enforced() && curve == cert.Curve_CURVE25519 {
			return errors.New("use of Curve25519 is not allowed in FIPS 140-only mode")
		}
	} else if isP11 {
		switch *cf.curve {
		case "P256":
			curve = cert.Curve_P256
		default:
			return fmt.Errorf("invalid curve for PKCS#11: %s", *cf.curve)
		}
	} else {
		c, ok := curveFlag(*cf.curve)
		switch {
		case !ok:
			return fmt.Errorf("invalid curve: %s", *cf.curve)
		case c == cert.Curve_CURVE25519:
			if fips140.Enforced() {
				return errors.New("use of Curve25519 is not allowed in FIPS 140-only mode")
			}
			pub, rawPriv = x25519Keypair()
			curve = cert.Curve_CURVE25519
		default:
			pub, rawPriv = p256Keypair()
			curve = cert.Curve_P256
		}
	}

	if version == cert.Version3 {
		pub, rawPriv, err = appendPQKey(suite, pub, rawPriv)
		if err != nil {
			return err
		}
	}

	if !isP11 && !isStdio(*cf.outKeyPath) {
		if _, err := os.Stat(*cf.outKeyPath); err == nil {
			return fmt.Errorf("refusing to overwrite existing key: %s", *cf.outKeyPath)
		}
	}

	if !isStdio(*cf.outPubPath) {
		if _, err := os.Stat(*cf.outPubPath); err == nil {
			return fmt.Errorf("refusing to overwrite existing public key: %s", *cf.outPubPath)
		}
	}

	if err := reserveOutputs(&claims,
		"out-key", *cf.outKeyPath,
		"out-pub", *cf.outPubPath,
	); err != nil {
		return err
	}

	if isP11 {
		p11Client, err := pkclient.FromUrl(*cf.p11url)
		if err != nil {
			return fmt.Errorf("error while creating PKCS#11 client: %w", err)
		}
		defer func(client *pkclient.PKClient) {
			_ = client.Close()
		}(p11Client)
		pub, err = p11Client.GetPubKey()
		if err != nil {
			return fmt.Errorf("error while getting public key: %w", err)
		}
	} else {
		b := cert.MarshalPrivateKeyToPEM(curve, rawPriv)
		if version == cert.Version3 {
			b = cert.MarshalPQPrivateKeyToPEM(curve, suite, rawPriv)
		}
		err = writeOutput(*cf.outKeyPath, b, 0600, out)
		if err != nil {
			return fmt.Errorf("error while writing out-key: %s", err)
		}
	}
	b := cert.MarshalPublicKeyToPEM(curve, pub)
	if version == cert.Version3 {
		b = cert.MarshalPQPublicKeyToPEM(curve, suite, pub)
	}
	err = writeOutput(*cf.outPubPath, b, 0600, out)
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
	_, _ = out.Write([]byte("Usage of " + os.Args[0] + " " + keygenSummary() + "\n"))
	_, _ = out.Write([]byte(stdioHelpText))
	cf.set.SetOutput(out)
	cf.set.PrintDefaults()
}

// curveFlag returns the curve a -curve value names, false for an unknown one.
func curveFlag(s string) (cert.Curve, bool) {
	switch s {
	case "25519", "X25519", "Curve25519", "CURVE25519":
		return cert.Curve_CURVE25519, true
	case "P256":
		return cert.Curve_P256, true
	}
	return 0, false
}
