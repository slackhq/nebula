package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/pkclient"
	"golang.org/x/crypto/ed25519"
)

type caFlags struct {
	set              *flag.FlagSet
	name             *string
	duration         *time.Duration
	outKeyPath       *string
	outCertPath      *string
	outQRPath        *string
	groups           *string
	networks         *string
	unsafeNetworks   *string
	argonMemory      *uint
	argonIterations  *uint
	argonParallelism *uint
	encryption       *bool
	version          *uint

	curve  *string
	p11url *string

	// Deprecated options
	ips     *string
	subnets *string
}

func newCaFlags() *caFlags {
	cf := caFlags{set: flag.NewFlagSet("ca", flag.ContinueOnError)}
	cf.set.Usage = func() {}
	cf.name = cf.set.String("name", "", "Required: name of the certificate authority")
	cf.version = cf.set.Uint("version", uint(cert.Version2), "Optional: version of the certificate format to use")
	cf.duration = cf.set.Duration("duration", time.Duration(time.Hour*8760), "Optional: amount of time the certificate should be valid for. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\"")
	cf.outKeyPath = cf.set.String("out-key", "ca.key", "Optional: path to write the private key to")
	cf.outCertPath = cf.set.String("out-crt", "ca.crt", "Optional: path to write the certificate to")
	cf.outQRPath = cf.set.String("out-qr", "", "Optional: output a qr code image (png) of the certificate")
	cf.groups = cf.set.String("groups", "", "Optional: comma separated list of groups. This will limit which groups subordinate certs can use")
	cf.networks = cf.set.String("networks", "", "Optional: comma separated list of ip address and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use in networks")
	cf.unsafeNetworks = cf.set.String("unsafe-networks", "", "Optional: comma separated list of ip address and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use in unsafe networks")
	cf.argonMemory = cf.set.Uint("argon-memory", 2*1024*1024, "Optional: Argon2 memory parameter (in KiB) used for encrypted private key passphrase")
	cf.argonParallelism = cf.set.Uint("argon-parallelism", 4, "Optional: Argon2 parallelism parameter used for encrypted private key passphrase")
	cf.argonIterations = cf.set.Uint("argon-iterations", 1, "Optional: Argon2 iterations parameter used for encrypted private key passphrase")
	cf.encryption = cf.set.Bool("encrypt", false, "Optional: prompt for passphrase and write out-key in an encrypted format")
	cf.curve = cf.set.String("curve", "25519", "EdDSA/ECDSA Curve (25519, P256)")
	cf.p11url = p11Flag(cf.set)

	cf.ips = cf.set.String("ips", "", "Deprecated, see -networks")
	cf.subnets = cf.set.String("subnets", "", "Deprecated, see -unsafe-networks")
	return &cf
}

func parseArgonParameters(memory uint, parallelism uint, iterations uint) (*cert.Argon2Parameters, error) {
	if memory <= 0 || memory > math.MaxUint32 {
		return nil, newHelpErrorf("-argon-memory must be be greater than 0 and no more than %d KiB", uint32(math.MaxUint32))
	}
	if parallelism <= 0 || parallelism > math.MaxUint8 {
		return nil, newHelpErrorf("-argon-parallelism must be be greater than 0 and no more than %d", math.MaxUint8)
	}
	if iterations <= 0 || iterations > math.MaxUint32 {
		return nil, newHelpErrorf("-argon-iterations must be be greater than 0 and no more than %d", uint32(math.MaxUint32))
	}

	return cert.NewArgon2Parameters(uint32(memory), uint8(parallelism), uint32(iterations)), nil
}

func ca(args []string, out io.Writer, errOut io.Writer, pr PasswordReader) error {
	cf := newCaFlags()
	err := cf.set.Parse(args)
	if err != nil {
		return err
	}

	isP11 := len(*cf.p11url) > 0

	if err := mustFlagString("name", cf.name); err != nil {
		return err
	}
	if !isP11 {
		if err = mustFlagString("out-key", cf.outKeyPath); err != nil {
			return err
		}
	}
	if err := mustFlagString("out-crt", cf.outCertPath); err != nil {
		return err
	}
	var kdfParams *cert.Argon2Parameters
	if !isP11 && *cf.encryption {
		if kdfParams, err = parseArgonParameters(*cf.argonMemory, *cf.argonParallelism, *cf.argonIterations); err != nil {
			return err
		}
	}

	if *cf.duration <= 0 {
		return &helpError{"-duration must be greater than 0"}
	}

	var groups []string
	if *cf.groups != "" {
		for _, rg := range strings.Split(*cf.groups, ",") {
			g := strings.TrimSpace(rg)
			if g != "" {
				groups = append(groups, g)
			}
		}
	}

	version := cert.Version(*cf.version)
	if version != cert.Version1 && version != cert.Version2 {
		return newHelpErrorf("-version must be either %v or %v", cert.Version1, cert.Version2)
	}

	var networks []netip.Prefix
	if *cf.networks == "" && *cf.ips != "" {
		// Pull up deprecated -ips flag if needed
		*cf.networks = *cf.ips
	}

	if *cf.networks != "" {
		for _, rs := range strings.Split(*cf.networks, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				n, err := netip.ParsePrefix(rs)
				if err != nil {
					return newHelpErrorf("invalid -networks definition: %s", rs)
				}
				if version == cert.Version1 && !n.Addr().Is4() {
					return newHelpErrorf("invalid -networks definition: v1 certificates can only be ipv4, have %s", rs)
				}
				networks = append(networks, n)
			}
		}
	}

	var unsafeNetworks []netip.Prefix
	if *cf.unsafeNetworks == "" && *cf.subnets != "" {
		// Pull up deprecated -subnets flag if needed
		*cf.unsafeNetworks = *cf.subnets
	}

	if *cf.unsafeNetworks != "" {
		for _, rs := range strings.Split(*cf.unsafeNetworks, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				n, err := netip.ParsePrefix(rs)
				if err != nil {
					return newHelpErrorf("invalid -unsafe-networks definition: %s", rs)
				}
				if version == cert.Version1 && !n.Addr().Is4() {
					return newHelpErrorf("invalid -unsafe-networks definition: v1 certificates can only be ipv4, have %s", rs)
				}
				unsafeNetworks = append(unsafeNetworks, n)
			}
		}
	}

	var passphrase []byte
	if !isP11 && *cf.encryption {
		passphrase = []byte(os.Getenv("NEBULA_CA_PASSPHRASE"))
		if len(passphrase) == 0 {
			for i := 0; i < 5; i++ {
				out.Write([]byte("Enter passphrase: "))
				passphrase, err = pr.ReadPassword()

				if err == ErrNoTerminal {
					return fmt.Errorf("out-key must be encrypted interactively")
				} else if err != nil {
					return fmt.Errorf("error reading passphrase: %s", err)
				}

				if len(passphrase) > 0 {
					break
				}
			}

			if len(passphrase) == 0 {
				return fmt.Errorf("no passphrase specified, remove -encrypt flag to write out-key in plaintext")
			}
		}
	}

	var curve cert.Curve
	var pub, rawPriv []byte
	var p11Client *pkclient.PKClient

	if isP11 {
		switch *cf.curve {
		case "P256":
			curve = cert.Curve_P256
		default:
			return fmt.Errorf("invalid curve for PKCS#11: %s", *cf.curve)
		}

		p11Client, err = pkclient.FromUrl(*cf.p11url)
		if err != nil {
			return fmt.Errorf("error while creating PKCS#11 client: %w", err)
		}
		defer func(client *pkclient.PKClient) {
			_ = client.Close()
		}(p11Client)
		pub, err = p11Client.GetPubKey()
		if err != nil {
			return fmt.Errorf("error while getting public key with PKCS#11: %w", err)
		}
	} else {
		switch *cf.curve {
		case "25519", "X25519", "Curve25519", "CURVE25519":
			curve = cert.Curve_CURVE25519
			pub, rawPriv, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("error while generating ed25519 keys: %s", err)
			}
		case "P256":
			var key *ecdsa.PrivateKey
			curve = cert.Curve_P256
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return fmt.Errorf("error while generating ecdsa keys: %s", err)
			}

			// ecdh.PrivateKey lets us get at the encoded bytes, even though
			// we aren't using ECDH here.
			eKey, err := key.ECDH()
			if err != nil {
				return fmt.Errorf("error while converting ecdsa key: %s", err)
			}
			rawPriv = eKey.Bytes()
			pub = eKey.PublicKey().Bytes()
		default:
			return fmt.Errorf("invalid curve: %s", *cf.curve)
		}
	}

	t := &cert.TBSCertificate{
		Version:        version,
		Name:           *cf.name,
		Groups:         groups,
		Networks:       networks,
		UnsafeNetworks: unsafeNetworks,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(*cf.duration),
		PublicKey:      pub,
		IsCA:           true,
		Curve:          curve,
	}

	if !isP11 {
		if _, err := os.Stat(*cf.outKeyPath); err == nil {
			return fmt.Errorf("refusing to overwrite existing CA key: %s", *cf.outKeyPath)
		}
	}

	if _, err := os.Stat(*cf.outCertPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing CA cert: %s", *cf.outCertPath)
	}

	var c cert.Certificate
	var b []byte

	if isP11 {
		c, err = t.SignWith(nil, curve, p11Client.SignASN1)
		if err != nil {
			return fmt.Errorf("error while signing with PKCS#11: %w", err)
		}
	} else {
		c, err = t.Sign(nil, curve, rawPriv)
		if err != nil {
			return fmt.Errorf("error while signing: %s", err)
		}

		if *cf.encryption {
			b, err = cert.EncryptAndMarshalSigningPrivateKey(curve, rawPriv, passphrase, kdfParams)
			if err != nil {
				return fmt.Errorf("error while encrypting out-key: %s", err)
			}
		} else {
			b = cert.MarshalSigningPrivateKeyToPEM(curve, rawPriv)
		}

		err = os.WriteFile(*cf.outKeyPath, b, 0600)
		if err != nil {
			return fmt.Errorf("error while writing out-key: %s", err)
		}
	}

	b, err = c.MarshalPEM()
	if err != nil {
		return fmt.Errorf("error while marshalling certificate: %s", err)
	}

	err = os.WriteFile(*cf.outCertPath, b, 0600)
	if err != nil {
		return fmt.Errorf("error while writing out-crt: %s", err)
	}

	if *cf.outQRPath != "" {
		b, err = qrcode.Encode(string(b), qrcode.Medium, -5)
		if err != nil {
			return fmt.Errorf("error while generating qr code: %s", err)
		}

		err = os.WriteFile(*cf.outQRPath, b, 0600)
		if err != nil {
			return fmt.Errorf("error while writing out-qr: %s", err)
		}
	}

	return nil
}

func caSummary() string {
	return "ca <flags>: create a self signed certificate authority"
}

func caHelp(out io.Writer) {
	cf := newCaFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + caSummary() + "\n"))
	cf.set.SetOutput(out)
	cf.set.PrintDefaults()
}
