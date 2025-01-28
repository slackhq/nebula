package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
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
	set            *flag.FlagSet
	version        *uint
	caKeyPath      *string
	caCertPath     *string
	name           *string
	networks       *string
	unsafeNetworks *string
	duration       *time.Duration
	inPubPath      *string
	outKeyPath     *string
	outCertPath    *string
	outQRPath      *string
	groups         *string

	p11url *string

	// Deprecated options
	ip      *string
	subnets *string
}

func newSignFlags() *signFlags {
	sf := signFlags{set: flag.NewFlagSet("sign", flag.ContinueOnError)}
	sf.set.Usage = func() {}
	sf.version = sf.set.Uint("version", 0, "Optional: version of the certificate format to use, the default is to create both v1 and v2 certificates.")
	sf.caKeyPath = sf.set.String("ca-key", "ca.key", "Optional: path to the signing CA key")
	sf.caCertPath = sf.set.String("ca-crt", "ca.crt", "Optional: path to the signing CA cert")
	sf.name = sf.set.String("name", "", "Required: name of the cert, usually a hostname")
	sf.networks = sf.set.String("networks", "", "Required: comma separated list of ip address and network in CIDR notation to assign to this cert")
	sf.unsafeNetworks = sf.set.String("unsafe-networks", "", "Optional: comma separated list of ip address and network in CIDR notation. Unsafe networks this cert can route for")
	sf.duration = sf.set.Duration("duration", 0, "Optional: how long the cert should be valid for. The default is 1 second before the signing cert expires. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\"")
	sf.inPubPath = sf.set.String("in-pub", "", "Optional (if out-key not set): path to read a previously generated public key")
	sf.outKeyPath = sf.set.String("out-key", "", "Optional (if in-pub not set): path to write the private key to")
	sf.outCertPath = sf.set.String("out-crt", "", "Optional: path to write the certificate to")
	sf.outQRPath = sf.set.String("out-qr", "", "Optional: output a qr code image (png) of the certificate")
	sf.groups = sf.set.String("groups", "", "Optional: comma separated list of groups")
	sf.p11url = p11Flag(sf.set)

	sf.ip = sf.set.String("ip", "", "Deprecated, see -networks")
	sf.subnets = sf.set.String("subnets", "", "Deprecated, see -unsafe-networks")
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
	if !isP11 && *sf.inPubPath != "" && *sf.outKeyPath != "" {
		return newHelpErrorf("cannot set both -in-pub and -out-key")
	}

	var v4Networks []netip.Prefix
	var v6Networks []netip.Prefix
	if *sf.networks == "" && *sf.ip != "" {
		// Pull up deprecated -ip flag if needed
		*sf.networks = *sf.ip
	}

	if len(*sf.networks) == 0 {
		return newHelpErrorf("-networks is required")
	}

	version := cert.Version(*sf.version)
	if version != 0 && version != cert.Version1 && version != cert.Version2 {
		return newHelpErrorf("-version must be either %v or %v", cert.Version1, cert.Version2)
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
		if errors.Is(err, cert.ErrPrivateKeyEncrypted) {
			// ask for a passphrase until we get one
			var passphrase []byte
			for i := 0; i < 5; i++ {
				out.Write([]byte("Enter passphrase: "))
				passphrase, err = pr.ReadPassword()

				if errors.Is(err, ErrNoTerminal) {
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

	if *sf.networks != "" {
		for _, rs := range strings.Split(*sf.networks, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				n, err := netip.ParsePrefix(rs)
				if err != nil {
					return newHelpErrorf("invalid -networks definition: %s", rs)
				}

				if n.Addr().Is4() {
					v4Networks = append(v4Networks, n)
				} else {
					v6Networks = append(v6Networks, n)
				}
			}
		}
	}

	var v4UnsafeNetworks []netip.Prefix
	var v6UnsafeNetworks []netip.Prefix
	if *sf.unsafeNetworks == "" && *sf.subnets != "" {
		// Pull up deprecated -subnets flag if needed
		*sf.unsafeNetworks = *sf.subnets
	}

	if *sf.unsafeNetworks != "" {
		for _, rs := range strings.Split(*sf.unsafeNetworks, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				n, err := netip.ParsePrefix(rs)
				if err != nil {
					return newHelpErrorf("invalid -unsafe-networks definition: %s", rs)
				}

				if n.Addr().Is4() {
					v4UnsafeNetworks = append(v4UnsafeNetworks, n)
				} else {
					v6UnsafeNetworks = append(v6UnsafeNetworks, n)
				}
			}
		}
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

	if *sf.outKeyPath == "" {
		*sf.outKeyPath = *sf.name + ".key"
	}

	if *sf.outCertPath == "" {
		*sf.outCertPath = *sf.name + ".crt"
	}

	if _, err := os.Stat(*sf.outCertPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing cert: %s", *sf.outCertPath)
	}

	var crts []cert.Certificate

	notBefore := time.Now()
	notAfter := notBefore.Add(*sf.duration)

	if version == 0 || version == cert.Version1 {
		// Make sure we at least have an ip
		if len(v4Networks) != 1 {
			return newHelpErrorf("invalid -networks definition: v1 certificates can only have a single ipv4 address")
		}

		if version == cert.Version1 {
			// If we are asked to mint a v1 certificate only then we cant just ignore any v6 addresses
			if len(v6Networks) > 0 {
				return newHelpErrorf("invalid -networks definition: v1 certificates can only be ipv4")
			}

			if len(v6UnsafeNetworks) > 0 {
				return newHelpErrorf("invalid -unsafe-networks definition: v1 certificates can only be ipv4")
			}
		}

		t := &cert.TBSCertificate{
			Version:        cert.Version1,
			Name:           *sf.name,
			Networks:       []netip.Prefix{v4Networks[0]},
			Groups:         groups,
			UnsafeNetworks: v4UnsafeNetworks,
			NotBefore:      notBefore,
			NotAfter:       notAfter,
			PublicKey:      pub,
			IsCA:           false,
			Curve:          curve,
		}

		var nc cert.Certificate
		if p11Client == nil {
			nc, err = t.Sign(caCert, curve, caKey)
			if err != nil {
				return fmt.Errorf("error while signing: %w", err)
			}
		} else {
			nc, err = t.SignWith(caCert, curve, p11Client.SignASN1)
			if err != nil {
				return fmt.Errorf("error while signing with PKCS#11: %w", err)
			}
		}

		crts = append(crts, nc)
	}

	if version == 0 || version == cert.Version2 {
		t := &cert.TBSCertificate{
			Version:        cert.Version2,
			Name:           *sf.name,
			Networks:       append(v4Networks, v6Networks...),
			Groups:         groups,
			UnsafeNetworks: append(v4UnsafeNetworks, v6UnsafeNetworks...),
			NotBefore:      notBefore,
			NotAfter:       notAfter,
			PublicKey:      pub,
			IsCA:           false,
			Curve:          curve,
		}

		var nc cert.Certificate
		if p11Client == nil {
			nc, err = t.Sign(caCert, curve, caKey)
			if err != nil {
				return fmt.Errorf("error while signing: %w", err)
			}
		} else {
			nc, err = t.SignWith(caCert, curve, p11Client.SignASN1)
			if err != nil {
				return fmt.Errorf("error while signing with PKCS#11: %w", err)
			}
		}

		crts = append(crts, nc)
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

	var b []byte
	for _, c := range crts {
		sb, err := c.MarshalPEM()
		if err != nil {
			return fmt.Errorf("error while marshalling certificate: %s", err)
		}
		b = append(b, sb...)
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
