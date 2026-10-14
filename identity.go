package nebula

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/commands"
)

type identityFlags struct {
	Address string

	// addressSet records that -address was given at all. An address that was given and
	// is empty is refused, not read as "this node": a program passing a connection's
	// remote address through must get an error for a value it failed to fill in, not
	// the daemon's own identity to authorize against.
	addressSet bool
}

// setAddress is -address's setter. flag.Func rather than StringVar so that presence is
// known; its String is empty, which is what a client building a line from the schema
// sees as the default.
func (f *identityFlags) setAddress(v string) error {
	f.Address = v
	f.addressSet = true
	return nil
}

// hostIdentity is what identity reports: the identity a certificate asserts for a host,
// and nothing else. Every field is read from a certificate nebula verified when the
// tunnel came up, or from our own, which is what lets a program on this host make an
// authorization decision from it. Nebula drops an inbound packet whose source address is
// not in the sender's certificate, so the source address of a connection arriving over
// the overlay maps to the certificate reported here. The field names are an API: the
// info API serves this shape to programs that were not built against nebula.
type hostIdentity struct {
	Name           string         `json:"name"`
	VpnAddrs       []netip.Addr   `json:"vpnAddrs"`
	Networks       []netip.Prefix `json:"networks"`
	UnsafeNetworks []netip.Prefix `json:"unsafeNetworks"`
	Groups         []string       `json:"groups"`
	Fingerprint    string         `json:"fingerprint"`
	Issuer         string         `json:"issuer"`
	NotBefore      time.Time      `json:"notBefore"`
	NotAfter       time.Time      `json:"notAfter"`
	CertVersion    int            `json:"certVersion"`
}

// runIdentity answers for this node when no address is given, otherwise for whoever
// owns the address: this node, when it is one of ours, or the peer behind an
// established tunnel.
func runIdentity(ifce *Interface, args *identityFlags, a []string) (commands.Result, error) {
	// print-cert takes its address as an operand; this takes a flag, because the query
	// string of the info API names its parameters and an operand has no name there. One
	// spelling on every surface, so the mistake is named rather than ignored.
	if len(a) > 0 {
		return commands.Failed("identity takes the vpn addr as -address, not as an operand: identity -address %s", a[0]), nil
	}

	cs := ifce.pki.getCertState()

	var (
		crt         cert.Certificate
		fingerprint string
	)
	if !args.addressSet {
		if crt = ownCertificate(cs); crt == nil {
			return commands.Result{}, fmt.Errorf("no certificate is loaded")
		}
	} else {
		vpnAddr, err := parseVpnAddrWithOptionalPort(args.Address)
		if err != nil {
			return commands.Failed("The provided vpn addr could not be parsed: %s", args.Address), nil
		}

		crt, fingerprint = findCertificateForVpnAddr(cs, ifce.hostMap, vpnAddr)
		if crt == nil {
			return commands.NotFound("No active tunnel for vpn addr: %s", vpnAddr), nil
		}
	}

	id, err := newHostIdentity(crt, fingerprint)
	if err != nil {
		return commands.Result{}, err
	}

	return commands.Value(id), nil
}

// textIdentity is the human rendering, shared by every surface.
func textIdentity(id hostIdentity, w io.Writer) error {
	_, err := fmt.Fprintf(w,
		"name: %s\nvpn addrs: %s\nnetworks: %s\nunsafe networks: %s\ngroups: %s\nfingerprint: %s\nissuer: %s\nnot before: %s\nnot after: %s\ncert version: %d\n",
		id.Name,
		joinStringers(id.VpnAddrs),
		joinStringers(id.Networks),
		joinStringers(id.UnsafeNetworks),
		strings.Join(id.Groups, ", "),
		id.Fingerprint,
		id.Issuer,
		id.NotBefore.Format(time.RFC3339),
		id.NotAfter.Format(time.RFC3339),
		id.CertVersion,
	)
	return err
}

func joinStringers[T fmt.Stringer](in []T) string {
	parts := make([]string, 0, len(in))
	for _, v := range in {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// newHostIdentity reads the identity out of a certificate. fingerprint is the
// certificate's when the caller already holds it, as a verified peer certificate does,
// and "" to have it hashed here. Slices are always allocated so a host with no groups
// reports [] rather than null.
func newHostIdentity(crt cert.Certificate, fingerprint string) (hostIdentity, error) {
	if fingerprint == "" {
		fp, err := crt.Fingerprint()
		if err != nil {
			return hostIdentity{}, err
		}
		fingerprint = fp
	}

	networks, unsafeNetworks, groups := crt.Networks(), crt.UnsafeNetworks(), crt.Groups()
	id := hostIdentity{
		Name:           crt.Name(),
		VpnAddrs:       make([]netip.Addr, 0, len(networks)),
		Networks:       append(make([]netip.Prefix, 0, len(networks)), networks...),
		UnsafeNetworks: append(make([]netip.Prefix, 0, len(unsafeNetworks)), unsafeNetworks...),
		Groups:         append(make([]string, 0, len(groups)), groups...),
		Fingerprint:    fingerprint,
		Issuer:         crt.Issuer(),
		NotBefore:      crt.NotBefore(),
		NotAfter:       crt.NotAfter(),
		CertVersion:    int(crt.Version()),
	}
	for _, n := range networks {
		id.VpnAddrs = append(id.VpnAddrs, n.Addr())
	}

	return id, nil
}

// ownCertificate is this node's certificate in the version it initiates handshakes
// with. It is nil only when no certificate is loaded, which a running nebula never has.
func ownCertificate(cs *CertState) cert.Certificate {
	if cs == nil {
		return nil
	}
	return cs.getCertificate(cs.initiatingVersion)
}

// findCertificateForVpnAddr answers who owns a vpn address: this node, from its own
// certificate state, since the hostmap never carries an entry for ourselves, or the peer
// behind an established tunnel. The certificate is nil when the address is unknown,
// when the tunnel is still pending and when it is mid teardown. A peer's comes with the
// fingerprint nebula computed when it verified the certificate; our own comes with "",
// since none is kept for it. The lighthouse's DNS TXT lookup and identity both go
// through it, so the two surfaces cannot disagree about whose address it is.
func findCertificateForVpnAddr(cs *CertState, hostMap *HostMap, ip netip.Addr) (crt cert.Certificate, fingerprint string) {
	if cs != nil && cs.myVpnAddrsTable != nil && cs.myVpnAddrsTable.Contains(ip) {
		return ownCertificate(cs), ""
	}

	hostinfo := hostMap.QueryVpnAddr(ip)
	if hostinfo == nil {
		return nil, ""
	}

	cc := hostinfo.GetCert()
	if cc == nil {
		return nil, ""
	}

	return cc.Certificate, cc.Fingerprint
}

// parseVpnAddrWithOptionalPort reads a vpn address alone or with a port,
// 192.168.100.7:54321 or [fd00::1]:443, so a program can pass a connection's remote
// address through as its runtime reported it. A 4in6 address (::ffff:a.b.c.d) is
// unmapped, which is how an IPv4 peer arrives on a dual stack listener, and a zone is
// dropped, since no vpn address carries one.
func parseVpnAddrWithOptionalPort(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return netip.Addr{}, err
		}
		ip = ap.Addr()
	}

	return ip.Unmap().WithZone(""), nil
}
