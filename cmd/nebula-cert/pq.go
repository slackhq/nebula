package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/slackhq/nebula/cert"
)

// pqSuiteFlag adds -pq-suite to a flag set.
func pqSuiteFlag(set *flag.FlagSet, usage string) *string {
	var names []string
	for _, s := range cert.PQSuites() {
		names = append(names, s.String())
	}
	return set.String("pq-suite", cert.DefaultPQSuite.String(), usage+" ("+strings.Join(names, ", ")+")")
}

// parsePQSuiteFlag returns the suite -pq-suite names. Setting it is an error unless allowed, when the suite has no use
// or comes from elsewhere.
func parsePQSuiteFlag(set *flag.FlagSet, value string, allowed bool, why string) (cert.PQSuite, error) {
	given := false
	set.Visit(func(f *flag.Flag) {
		if f.Name == "pq-suite" {
			given = true
		}
	})
	if given && !allowed {
		return cert.PQSuiteUnknown, newHelpErrorf("-pq-suite %s", why)
	}
	s, err := cert.ParsePQSuite(value)
	if err != nil {
		return cert.PQSuiteUnknown, newHelpErrorf("-pq-suite: %s", err)
	}
	return s, nil
}

// appendPQSigningKey makes a classical CA keypair into a version 3 composite one with a fresh key of suite.
func appendPQSigningKey(suite cert.PQSuite, pub, priv []byte) ([]byte, []byte, error) {
	pqPub, pqPriv, err := suite.GenerateKey(true)
	if err != nil {
		return nil, nil, fmt.Errorf("error while generating %v CA key: %s", suite, err)
	}
	return append(pub, pqPub...), append(priv, pqPriv...), nil
}

// appendPQKey makes a classical host keypair into a version 3 composite one with a fresh key of suite.
func appendPQKey(suite cert.PQSuite, pub, priv []byte) ([]byte, []byte, error) {
	pqPub, pqPriv, err := suite.GenerateKey(false)
	if err != nil {
		return nil, nil, fmt.Errorf("error while generating %v key: %s", suite, err)
	}
	return append(pub, pqPub...), append(priv, pqPriv...), nil
}

// publicKeyFor returns the public key of a classical host private key.
func publicKeyFor(curve cert.Curve, priv []byte) ([]byte, error) {
	var c ecdh.Curve
	switch curve {
	case cert.Curve_CURVE25519:
		c = ecdh.X25519()
	case cert.Curve_P256:
		c = ecdh.P256()
	default:
		return nil, fmt.Errorf("invalid curve: %s", curve)
	}
	k, err := c.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("not a valid %s private key", curve)
	}
	return k.PublicKey().Bytes(), nil
}

type pqExtendFlags struct {
	set         *flag.FlagSet
	caKeyPath   *string
	caCertPath  *string
	inCertPath  *string
	inPubPath   *string
	outCertPath *string
	outKeyPath  *string
	inPQKeyPath *string
	pqSuite     *string
}

func newPQExtendFlags() *pqExtendFlags {
	pf := pqExtendFlags{set: flag.NewFlagSet("pq-extend", flag.ContinueOnError)}
	pf.set.Usage = func() {}
	pf.inCertPath = pf.set.String("in-crt", "", "Required: path to the version 2 certificate to extend, a CA or a host")
	pf.outCertPath = pf.set.String("out-crt", "", "Required: path to write the version 3 certificate to")
	pf.caKeyPath = pf.set.String("ca-key", "ca.key", "Optional: path to the CA key. For a CA in-crt, its own version 2 key. For a host in-crt, the version 3 key of the CA that issued it")
	pf.caCertPath = pf.set.String("ca-crt", "", "Required for a host in-crt: path to the version 3 form of the CA that issued it")
	pf.inPubPath = pf.set.String("in-pub", "", "Required for a host in-crt: path to the host's public key from keygen -in-key")
	pf.outKeyPath = pf.set.String("out-key", "", "Required for a CA in-crt without -in-pq-key: path to write the CA's version 3 key to, encrypted again if ca-key was")
	pf.inPQKeyPath = pf.set.String("in-pq-key", "", "Optional for a CA in-crt: path to the CA's version 3 key from an earlier pq-extend, whose post-quantum key is used again, so extending the same CA again gives the same version 3 CA. Without it a new post-quantum key is made")
	pf.pqSuite = pqSuiteFlag(pf.set, "Optional, for a CA in-crt: post-quantum suite of the version 3 CA. A host takes its CA's suite")
	return &pf
}

// pqExtend turns a version 2 certificate into a version 3 one in place: the v2 form, and so its fingerprint and
// existing trust in it, stays exactly as it was.
func pqExtend(args []string, out io.Writer, errOut io.Writer, pr PasswordReader) error {
	pf := newPQExtendFlags()
	if err := pf.set.Parse(args); err != nil {
		return err
	}
	if err := mustFlagString("in-crt", pf.inCertPath); err != nil {
		return err
	}
	if err := mustFlagString("out-crt", pf.outCertPath); err != nil {
		return err
	}
	if err := mustFlagString("ca-key", pf.caKeyPath); err != nil {
		return err
	}

	var claims ioClaims
	if err := reserveInputs(&claims,
		"in-crt", *pf.inCertPath,
		"ca-key", *pf.caKeyPath,
		"ca-crt", *pf.caCertPath,
		"in-pub", *pf.inPubPath,
		"in-pq-key", *pf.inPQKeyPath,
	); err != nil {
		return err
	}
	if err := reserveOutputs(&claims,
		"out-crt", *pf.outCertPath,
		"out-key", *pf.outKeyPath,
	); err != nil {
		return err
	}

	rawCert, err := readInput("in-crt", *pf.inCertPath, &claims)
	if err != nil {
		return fmt.Errorf("error while reading in-crt: %s", err)
	}
	c, _, err := cert.UnmarshalCertificateFromPEM(rawCert)
	if err != nil {
		return fmt.Errorf("error while parsing in-crt: %s", err)
	}
	if c.Version() != cert.Version2 {
		return fmt.Errorf("only version 2 certificates extend to version 3, in-crt is version %d", c.Version())
	}

	for _, p := range []string{*pf.outCertPath, *pf.outKeyPath} {
		if p != "" && !isStdio(p) {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("refusing to overwrite existing file: %s", p)
			}
		}
	}

	rawCAKey, err := readInput("ca-key", *pf.caKeyPath, &claims)
	if err != nil {
		return fmt.Errorf("error while reading ca-key: %s", err)
	}
	curve, caKey, passphrase, err := readSigningKey(rawCAKey, errOut, pr)
	if err != nil {
		return err
	}

	suite, err := parsePQSuiteFlag(pf.set, *pf.pqSuite, c.IsCA(), "is for CA certificates, a host takes its CA's suite")
	if err != nil {
		return err
	}

	var c3 cert.Certificate
	if c.IsCA() {
		c3, err = extendCA(pf, c, suite, curve, caKey, rawCAKey, passphrase, out, errOut, pr, &claims)
	} else {
		if *pf.inPQKeyPath != "" {
			return newHelpErrorf("-in-pq-key is for CA certificates, a host's key comes from keygen -in-key")
		}
		c3, err = extendHost(pf, c, curve, caKey, &claims)
	}
	if err != nil {
		return err
	}

	b, err := c3.MarshalPEM()
	if err != nil {
		return fmt.Errorf("error while marshalling certificate: %s", err)
	}
	if err := writeOutput(*pf.outCertPath, b, 0600, out); err != nil {
		return fmt.Errorf("error while writing out-crt: %s", err)
	}
	return nil
}

// extendCA gives a v2 CA a post-quantum key of suite, a new one or that of -in-pq-key, and writes out the composite
// key. Extending is deterministic, so the same CA and post-quantum key give the same v3 CA every time.
func extendCA(pf *pqExtendFlags, ca cert.Certificate, suite cert.PQSuite, curve cert.Curve, key, rawKey, passphrase []byte, out, errOut io.Writer, pr PasswordReader, claims *ioClaims) (cert.Certificate, error) {
	if *pf.caCertPath != "" || *pf.inPubPath != "" {
		return nil, newHelpErrorf("-ca-crt and -in-pub are for host certificates, a CA extends itself")
	}
	if *pf.inPQKeyPath == "" {
		if err := mustFlagString("out-key", pf.outKeyPath); err != nil {
			return nil, err
		}
	}
	if err := ca.VerifyPrivateKey(curve, key); err != nil {
		return nil, fmt.Errorf("refusing to extend, the CA certificate does not match ca-key")
	}

	var pub, priv []byte
	if *pf.inPQKeyPath != "" {
		// Never derived from the classical key: that would hand the post-quantum key to whoever breaks the classical
		// one. It has to be the key an earlier run made.
		raw, err := readInput("in-pq-key", *pf.inPQKeyPath, claims)
		if err != nil {
			return nil, fmt.Errorf("error while reading in-pq-key: %s", err)
		}
		pqCurve, composite, _, err := readSigningKey(raw, errOut, pr)
		if err != nil {
			return nil, fmt.Errorf("error while parsing in-pq-key: %s", err)
		}
		classical, seed, err := suite.SplitPrivateKey(true, composite)
		if err != nil || pqCurve != curve || !bytes.Equal(classical, key) {
			return nil, fmt.Errorf("in-pq-key must be the %v version 3 key of this CA, from an earlier pq-extend of it", suite)
		}
		if pub, err = suite.DerivePublicKey(true, seed); err != nil {
			return nil, fmt.Errorf("error while parsing in-pq-key: %s", err)
		}
		priv = composite
	} else {
		var err error
		if pub, priv, err = appendPQSigningKey(suite, nil, append([]byte(nil), key...)); err != nil {
			return nil, err
		}
	}
	sign, err := cert.SignClassical(curve, key)
	if err != nil {
		return nil, err
	}
	signPQ, err := cert.SignPQ(suite, curve, priv[len(key):])
	if err != nil {
		return nil, err
	}
	c3, err := cert.ExtendToV3(ca, suite, pub, nil, sign, signPQ)
	if err != nil {
		return nil, fmt.Errorf("error while extending: %s", err)
	}
	if *pf.outKeyPath == "" {
		// The version 3 key is in-pq-key already.
		return c3, nil
	}

	var b []byte
	if passphrase != nil {
		// Encrypt it the way ca-key was, with a fresh salt.
		block, _ := pem.Decode(rawKey)
		if block == nil {
			return nil, fmt.Errorf("error while parsing ca-key: input did not contain a valid PEM encoded block")
		}
		ned, err := cert.UnmarshalNebulaEncryptedData(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error while parsing encrypted ca-key: %s", err)
		}
		a := ned.EncryptionMetadata.Argon2Parameters
		kdf := cert.NewArgon2Parameters(a.Memory, a.Parallelism, a.Iterations)
		b, err = cert.EncryptAndMarshalPQSigningPrivateKey(curve, suite, priv, passphrase, kdf)
		if err != nil {
			return nil, fmt.Errorf("error while encrypting out-key: %s", err)
		}
	} else {
		b = cert.MarshalPQSigningPrivateKeyToPEM(curve, suite, priv)
	}
	if err := writeOutput(*pf.outKeyPath, b, 0600, out); err != nil {
		return nil, fmt.Errorf("error while writing out-key: %s", err)
	}
	return c3, nil
}

// extendHost adds a host's post-quantum key to its certificate, signed by the v3 form of its CA, in the CA's suite.
func extendHost(pf *pqExtendFlags, c cert.Certificate, curve cert.Curve, caKey []byte, claims *ioClaims) (cert.Certificate, error) {
	if *pf.outKeyPath != "" {
		return nil, newHelpErrorf("-out-key is for CA certificates, a host's key comes from keygen -in-key")
	}
	if err := mustFlagString("ca-crt", pf.caCertPath); err != nil {
		return nil, err
	}
	if err := mustFlagString("in-pub", pf.inPubPath); err != nil {
		return nil, err
	}

	rawCA, err := readInput("ca-crt", *pf.caCertPath, claims)
	if err != nil {
		return nil, fmt.Errorf("error while reading ca-crt: %s", err)
	}
	ca, _, err := cert.UnmarshalCertificateFromPEM(rawCA)
	if err != nil {
		return nil, fmt.Errorf("error while parsing ca-crt: %s", err)
	}
	if ca.Version() != cert.Version3 {
		return nil, fmt.Errorf("ca-crt must be a version 3 CA, extend the CA first")
	}
	if err := ca.VerifyPrivateKey(curve, caKey); err != nil {
		return nil, fmt.Errorf("refusing to extend, ca-crt does not match ca-key")
	}

	rawPub, err := readInput("in-pub", *pf.inPubPath, claims)
	if err != nil {
		return nil, fmt.Errorf("error while reading in-pub: %s", err)
	}
	pub, _, pubCurve, err := cert.UnmarshalPublicKeyFromPEM(rawPub)
	if err != nil {
		return nil, fmt.Errorf("error while parsing in-pub: %s", err)
	}
	suite := cert.PQSuiteOf(ca)
	classical, pq, err := suite.SplitPublicKey(false, pub)
	if pubCurve != c.Curve() || err != nil {
		return nil, fmt.Errorf("in-pub must be the host's key from keygen -in-key -pq-suite %v", suite)
	}
	if !bytes.Equal(classical, c.PublicKey()) {
		return nil, fmt.Errorf("in-pub does not extend the key in in-crt")
	}

	classicalCAKey, pqCAKey, err := suite.SplitPrivateKey(true, caKey)
	if err != nil {
		return nil, err
	}
	sign, err := cert.SignClassical(curve, classicalCAKey)
	if err != nil {
		return nil, err
	}
	signPQ, err := cert.SignPQ(suite, curve, pqCAKey)
	if err != nil {
		return nil, err
	}
	c3, err := cert.ExtendToV3(c, suite, pq, ca, sign, signPQ)
	if err != nil {
		return nil, fmt.Errorf("error while extending: %s", err)
	}
	return c3, nil
}

func pqExtendSummary() string {
	return "pq-extend <flags>: extend a version 2 CA or host certificate to version 3 in place, keeping its v2 form and fingerprint"
}

func pqExtendHelp(out io.Writer) {
	pf := newPQExtendFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + pqExtendSummary() + "\n"))
	out.Write([]byte(stdioHelpText))
	pf.set.SetOutput(out)
	pf.set.PrintDefaults()
}
