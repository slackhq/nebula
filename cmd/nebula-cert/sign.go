package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/pkclient"
	"golang.org/x/crypto/curve25519"
)

type signFlags struct {
	set         *flag.FlagSet
	caKeyPath   *string
	caCertPath  *string
	name        *string
	ip          *string
	duration    *time.Duration
	inPubPath   *string
	outKeyPath  *string
	outCertPath *string
	outQRPath   *string
	groups      *string
	subnets     *string
	p11url      *string
}

func newSignFlags() *signFlags {
	sf := signFlags{set: flag.NewFlagSet("sign", flag.ContinueOnError)}
	sf.set.Usage = func() {}
	sf.caKeyPath = sf.set.String("ca-key", "ca.key", "Optional: path to the signing CA key")
	sf.caCertPath = sf.set.String("ca-crt", "ca.crt", "Optional: path to the signing CA cert")
	sf.name = sf.set.String("name", "", "Required: name of the cert, usually a hostname")
	sf.ip = sf.set.String("ip", "", "Required: ipv4 address and network in CIDR notation to assign the cert")
	sf.duration = sf.set.Duration("duration", 0, "Optional: how long the cert should be valid for. The default is 1 second before the signing cert expires. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\"")
	sf.inPubPath = sf.set.String("in-pub", "", "Optional (if out-key not set): path to read a previously generated public key")
	sf.outKeyPath = sf.set.String("out-key", "", "Optional (if in-pub not set): path to write the private key to")
	sf.outCertPath = sf.set.String("out-crt", "", "Optional: path to write the certificate to")
	sf.outQRPath = sf.set.String("out-qr", "", "Optional: output a qr code image (png) of the certificate")
	sf.groups = sf.set.String("groups", "", "Optional: comma separated list of groups")
	sf.subnets = sf.set.String("subnets", "", "Optional: comma separated list of ipv4 address and network in CIDR notation. Subnets this cert can serve for")
	sf.p11url = p11Flag(sf.set)
	return &sf
}

func signCert(args []string, out io.Writer, errOut io.Writer, pr PasswordReader) error {
	sf := newSignFlags()
	err := sf.set.Parse(args)
	if err != nil {
		return err
	}

	isP11 := len(*sf.p11url) > 0

	if !isP11 {
		if err := mustFlagString("ca-key", sf.caKeyPath); err != nil {
			return err
		}
	}
	if err := mustFlagString("ca-crt", sf.caCertPath); err != nil {
		return err
	}
	if err := mustFlagString("name", sf.name); err != nil {
		return err
	}
	if err := mustFlagString("ip", sf.ip); err != nil {
		return err
	}
	if !isP11 && *sf.inPubPath != "" && *sf.outKeyPath != "" {
		return newHelpErrorf("cannot set both -in-pub and -out-key")
	}

	var curve cert.Curve
	var caKey []byte

	if !isP11 {
		var rawCAKey []byte
		rawCAKey, err := os.ReadFile(*sf.caKeyPath)

		if err != nil {
			return fmt.Errorf("error while reading ca-key: %s", err)
		}

		// naively attempt to decode the private key as though it is not encrypted
		caKey, _, curve, err = cert.UnmarshalSigningPrivateKeyFromPEM(rawCAKey)
		if err == cert.ErrPrivateKeyEncrypted {
			// ask for a passphrase until we get one
			var passphrase []byte
			for i := 0; i < 5; i++ {
				out.Write([]byte("Enter passphrase: "))
				passphrase, err = pr.ReadPassword()

				if err == ErrNoTerminal {
					return fmt.Errorf("ca-key is encrypted and must be decrypted interactively")
				} else if err != nil {
					return fmt.Errorf("error reading password: %s", err)
				}

				if len(passphrase) > 0 {
					break
				}
			}
			if len(passphrase) == 0 {
				return fmt.Errorf("cannot open encrypted ca-key without passphrase")
			}

			curve, caKey, _, err = cert.DecryptAndUnmarshalSigningPrivateKey(passphrase, rawCAKey)
			if err != nil {
				return fmt.Errorf("error while parsing encrypted ca-key: %s", err)
			}
		} else if err != nil {
			return fmt.Errorf("error while parsing ca-key: %s", err)
		}
	}

	rawCACert, err := os.ReadFile(*sf.caCertPath)
	if err != nil {
		return fmt.Errorf("error while reading ca-crt: %s", err)
	}

	caCert, _, err := cert.UnmarshalCertificateFromPEM(rawCACert)
	if err != nil {
		return fmt.Errorf("error while parsing ca-crt: %s", err)
	}

	if !isP11 {
		if err := caCert.VerifyPrivateKey(curve, caKey); err != nil {
			return fmt.Errorf("refusing to sign, root certificate does not match private key")
		}
	}

	if caCert.Expired(time.Now()) {
		return fmt.Errorf("ca certificate is expired")
	}

	// if no duration is given, expire one second before the root expires
	if *sf.duration <= 0 {
		*sf.duration = time.Until(caCert.NotAfter()) - time.Second*1
	}

	network, err := netip.ParsePrefix(*sf.ip)
	if err != nil {
		return newHelpErrorf("invalid ip definition: %s", err)
	}
	if !network.Addr().Is4() {
		return newHelpErrorf("invalid ip definition: can only be ipv4, have %s", *sf.ip)
	}

	var groups []string
	if *sf.groups != "" {
		for _, rg := range strings.Split(*sf.groups, ",") {
			g := strings.TrimSpace(rg)
			if g != "" {
				groups = append(groups, g)
			}
		}
	}

	var subnets []netip.Prefix
	if *sf.subnets != "" {
		for _, rs := range strings.Split(*sf.subnets, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				s, err := netip.ParsePrefix(rs)
				if err != nil {
					return newHelpErrorf("invalid subnet definition: %s", err)
				}
				if !s.Addr().Is4() {
					return newHelpErrorf("invalid subnet definition: can only be ipv4, have %s", rs)
				}
				subnets = append(subnets, s)
			}
		}
	}

	var pub, rawPriv []byte
	var p11Client *pkclient.PKClient

	if isP11 {
		curve = cert.Curve_P256
		p11Client, err = pkclient.FromUrl(*sf.p11url)
		if err != nil {
			return fmt.Errorf("error while creating PKCS#11 client: %w", err)
		}
		defer func(client *pkclient.PKClient) {
			_ = client.Close()
		}(p11Client)
	}

	if *sf.inPubPath != "" {
		var pubCurve cert.Curve
		rawPub, err := os.ReadFile(*sf.inPubPath)
		if err != nil {
			return fmt.Errorf("error while reading in-pub: %s", err)
		}

		pub, _, pubCurve, err = cert.UnmarshalPublicKeyFromPEM(rawPub)
		if err != nil {
			return fmt.Errorf("error while parsing in-pub: %s", err)
		}
		if pubCurve != curve {
			return fmt.Errorf("curve of in-pub does not match ca")
		}
	} else if isP11 {
		pub, err = p11Client.GetPubKey()
		if err != nil {
			return fmt.Errorf("error while getting public key with PKCS#11: %w", err)
		}
	} else {
		pub, rawPriv = newKeypair(curve)
	}

	t := &cert.TBSCertificate{
		Version:        cert.Version1,
		Name:           *sf.name,
		Networks:       []netip.Prefix{network},
		Groups:         groups,
		UnsafeNetworks: subnets,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(*sf.duration),
		PublicKey:      pub,
		IsCA:           false,
		Curve:          curve,
	}

	var c cert.Certificate

	if p11Client == nil {
		c, err = t.Sign(caCert, curve, caKey)
		if err != nil {
			return fmt.Errorf("error while signing: %w", err)
		}
	} else {
		c, err = t.SignPkcs11(caCert, curve, p11Client)
		if err != nil {
			return fmt.Errorf("error while signing with PKCS#11: %w", err)
		}
	}

	//TODO:
	//if err := nc.CheckRootConstrains(caCert); err != nil {
	//	return fmt.Errorf("refusing to sign, root certificate constraints violated: %s", err)
	//}

	if *sf.outKeyPath == "" {
		*sf.outKeyPath = *sf.name + ".key"
	}

	if *sf.outCertPath == "" {
		*sf.outCertPath = *sf.name + ".crt"
	}

	if _, err := os.Stat(*sf.outCertPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing cert: %s", *sf.outCertPath)
	}

	if !isP11 && *sf.inPubPath == "" {
		if _, err := os.Stat(*sf.outKeyPath); err == nil {
			return fmt.Errorf("refusing to overwrite existing key: %s", *sf.outKeyPath)
		}

		err = os.WriteFile(*sf.outKeyPath, cert.MarshalPrivateKeyToPEM(curve, rawPriv), 0600)
		if err != nil {
			return fmt.Errorf("error while writing out-key: %s", err)
		}
	}

	b, err := c.MarshalToPEM()
	if err != nil {
		return fmt.Errorf("error while marshalling certificate: %s", err)
	}

	err = os.WriteFile(*sf.outCertPath, b, 0600)
	if err != nil {
		return fmt.Errorf("error while writing out-crt: %s", err)
	}

	if *sf.outQRPath != "" {
		b, err = qrcode.Encode(string(b), qrcode.Medium, -5)
		if err != nil {
			return fmt.Errorf("error while generating qr code: %s", err)
		}

		err = os.WriteFile(*sf.outQRPath, b, 0600)
		if err != nil {
			return fmt.Errorf("error while writing out-qr: %s", err)
		}
	}

	return nil
}

func newKeypair(curve cert.Curve) ([]byte, []byte) {
	switch curve {
	case cert.Curve_CURVE25519:
		return x25519Keypair()
	case cert.Curve_P256:
		return p256Keypair()
	default:
		return nil, nil
	}
}

func x25519Keypair() ([]byte, []byte) {
	privkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privkey); err != nil {
		panic(err)
	}

	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}

	return pubkey, privkey
}

func p256Keypair() ([]byte, []byte) {
	privkey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey := privkey.PublicKey()
	return pubkey.Bytes(), privkey.Bytes()
}

func signSummary() string {
	return "sign <flags>: create and sign a certificate"
}

func signHelp(out io.Writer) {
	sf := newSignFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + signSummary() + "\n"))
	sf.set.SetOutput(out)
	sf.set.PrintDefaults()
}
