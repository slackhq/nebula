package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mldsa"
	"crypto/mlkem"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/slackhq/nebula/cert"
)

// appendPQSigningKey makes a classical CA keypair into a version 3 composite one with a fresh ML-DSA-87 key.
func appendPQSigningKey(pub, priv []byte) ([]byte, []byte, error) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, nil, fmt.Errorf("error while generating ML-DSA-87 key: %s", err)
	}
	return append(pub, sk.PublicKey().Bytes()...), append(priv, sk.Bytes()...), nil
}

// appendPQKey makes a classical host keypair into a version 3 composite one with a fresh ML-KEM-1024 key.
func appendPQKey(pub, priv []byte) ([]byte, []byte, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, fmt.Errorf("error while generating ML-KEM-1024 key: %s", err)
	}
	return append(pub, dk.EncapsulationKey().Bytes()...), append(priv, dk.Bytes()...), nil
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
		return nil, fmt.Errorf("not a classical %s private key, it may already have an ML-KEM-1024 key", curve)
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
}

func newPQExtendFlags() *pqExtendFlags {
	pf := pqExtendFlags{set: flag.NewFlagSet("pq-extend", flag.ContinueOnError)}
	pf.set.Usage = func() {}
	pf.inCertPath = pf.set.String("in-crt", "", "Required: path to the version 2 certificate to extend, a CA or a host")
	pf.outCertPath = pf.set.String("out-crt", "", "Required: path to write the version 3 certificate to")
	pf.caKeyPath = pf.set.String("ca-key", "ca.key", "Optional: path to the CA key. For a CA in-crt, its own version 2 key. For a host in-crt, the version 3 key of the CA that issued it")
	pf.caCertPath = pf.set.String("ca-crt", "", "Required for a host in-crt: path to the version 3 form of the CA that issued it")
	pf.inPubPath = pf.set.String("in-pub", "", "Required for a host in-crt: path to the host's public key from keygen -in-key")
	pf.outKeyPath = pf.set.String("out-key", "", "Required for a CA in-crt: path to write the CA's version 3 key to, encrypted again if ca-key was")
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

	var c3 cert.Certificate
	if c.IsCA() {
		c3, err = extendCA(pf, c, curve, caKey, rawCAKey, passphrase, out)
	} else {
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

// extendCA gives a v2 CA an ML-DSA-87 key and writes out the composite key.
func extendCA(pf *pqExtendFlags, ca cert.Certificate, curve cert.Curve, key, rawKey, passphrase []byte, out io.Writer) (cert.Certificate, error) {
	if *pf.caCertPath != "" || *pf.inPubPath != "" {
		return nil, newHelpErrorf("-ca-crt and -in-pub are for host certificates, a CA extends itself")
	}
	if err := mustFlagString("out-key", pf.outKeyPath); err != nil {
		return nil, err
	}
	if err := ca.VerifyPrivateKey(curve, key); err != nil {
		return nil, fmt.Errorf("refusing to extend, the CA certificate does not match ca-key")
	}

	pub, priv, err := appendPQSigningKey(nil, append([]byte(nil), key...))
	if err != nil {
		return nil, err
	}
	signPQ, err := cert.SignPQ(priv[len(key):])
	if err != nil {
		return nil, err
	}
	c3, err := cert.ExtendToV3(ca, pub, nil, signPQ)
	if err != nil {
		return nil, fmt.Errorf("error while extending: %s", err)
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
		b, err = cert.EncryptAndMarshalSigningPrivateKey(curve, priv, passphrase, kdf)
		if err != nil {
			return nil, fmt.Errorf("error while encrypting out-key: %s", err)
		}
	} else {
		b = cert.MarshalSigningPrivateKeyToPEM(curve, priv)
	}
	if err := writeOutput(*pf.outKeyPath, b, 0600, out); err != nil {
		return nil, fmt.Errorf("error while writing out-key: %s", err)
	}
	return c3, nil
}

// extendHost adds a host's ML-KEM-1024 key to its certificate, signed by the v3 form of its CA.
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
	if pubCurve != c.Curve() || len(pub) <= cert.MLKEM1024PublicKeySize {
		return nil, fmt.Errorf("in-pub must be the host's key from keygen -in-key")
	}
	classical, pq := pub[:len(pub)-cert.MLKEM1024PublicKeySize], pub[len(pub)-cert.MLKEM1024PublicKeySize:]
	if !bytes.Equal(classical, c.PublicKey()) {
		return nil, fmt.Errorf("in-pub does not extend the key in in-crt")
	}

	signPQ, err := cert.SignPQ(caKey[len(caKey)-cert.MLDSA87PrivateKeySize:])
	if err != nil {
		return nil, err
	}
	c3, err := cert.ExtendToV3(c, pq, ca, signPQ)
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
