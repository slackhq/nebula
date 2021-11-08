package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/ed25519"
)

type caFlags struct {
	set         *flag.FlagSet
	name        *string
	duration    *time.Duration
	outKeyPath  *string
	outCertPath *string
	outQRPath   *string
	groups      *string
	ips         *string
	subnets     *string
}

func newCaFlags() *caFlags {
	cf := caFlags{set: flag.NewFlagSet("ca", flag.ContinueOnError)}
	cf.set.Usage = func() {}
	cf.name = cf.set.String("name", "", "Required: name of the certificate authority")
	cf.duration = cf.set.Duration("duration", time.Duration(time.Hour*8760), "Optional: amount of time the certificate should be valid for. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\"")
	cf.outKeyPath = cf.set.String("out-key", "ca.key", "Optional: path to write the private key to")
	cf.outCertPath = cf.set.String("out-crt", "ca.crt", "Optional: path to write the certificate to")
	cf.outQRPath = cf.set.String("out-qr", "", "Optional: output a qr code image (png) of the certificate")
	cf.groups = cf.set.String("groups", "", "Optional: comma separated list of groups. This will limit which groups subordinate certs can use")
	cf.ips = cf.set.String("ips", "", "Optional: comma separated list of ip and network in CIDR notation. This will limit which ip addresses and networks subordinate certs can use")
	cf.subnets = cf.set.String("subnets", "", "Optional: comma separated list of ip and network in CIDR notation. This will limit which subnet addresses and networks subordinate certs can use")
	return &cf
}

func ca(args []string, out io.Writer, errOut io.Writer) error {
	cf := newCaFlags()
	err := cf.set.Parse(args)
	if err != nil {
		return err
	}

	if err := mustFlagString("name", cf.name); err != nil {
		return err
	}
	if err := mustFlagString("out-key", cf.outKeyPath); err != nil {
		return err
	}
	if err := mustFlagString("out-crt", cf.outCertPath); err != nil {
		return err
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

	var ips []*net.IPNet
	if *cf.ips != "" {
		for _, rs := range strings.Split(*cf.ips, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				ip, ipNet, err := net.ParseCIDR(rs)
				if err != nil {
					return newHelpErrorf("invalid ip definition: %s", err)
				}

				ipNet.IP = ip
				ips = append(ips, ipNet)
			}
		}
	}

	var subnets []*net.IPNet
	if *cf.subnets != "" {
		for _, rs := range strings.Split(*cf.subnets, ",") {
			rs := strings.Trim(rs, " ")
			if rs != "" {
				_, s, err := net.ParseCIDR(rs)
				if err != nil {
					return newHelpErrorf("invalid subnet definition: %s", err)
				}
				subnets = append(subnets, s)
			}
		}
	}

	pub, rawPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("error while generating ed25519 keys: %s", err)
	}

	nc := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      *cf.name,
			Groups:    groups,
			Ips:       ips,
			Subnets:   subnets,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(*cf.duration),
			PublicKey: pub,
			IsCA:      true,
		},
	}

	if _, err := os.Stat(*cf.outKeyPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing CA key: %s", *cf.outKeyPath)
	}

	if _, err := os.Stat(*cf.outCertPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing CA cert: %s", *cf.outCertPath)
	}

	err = nc.Sign(rawPriv)
	if err != nil {
		return fmt.Errorf("error while signing: %s", err)
	}

	err = ioutil.WriteFile(*cf.outKeyPath, cert.MarshalEd25519PrivateKey(rawPriv), 0600)
	if err != nil {
		return fmt.Errorf("error while writing out-key: %s", err)
	}

	b, err := nc.MarshalToPEM()
	if err != nil {
		return fmt.Errorf("error while marshalling certificate: %s", err)
	}

	err = ioutil.WriteFile(*cf.outCertPath, b, 0600)
	if err != nil {
		return fmt.Errorf("error while writing out-crt: %s", err)
	}

	if *cf.outQRPath != "" {
		b, err = qrcode.Encode(string(b), qrcode.Medium, -5)
		if err != nil {
			return fmt.Errorf("error while generating qr code: %s", err)
		}

		err = ioutil.WriteFile(*cf.outQRPath, b, 0600)
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
