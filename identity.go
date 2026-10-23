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
	// Pem answers with the certificate itself, PEM encoded, in place of the fields read
	// from it, for a program that verifies it against its own CAs. The info API serves
	// the same thing as the identity's pem sub-resource.
	Pem bool
}

// hostIdentity is what identity reports: the identity a certificate asserts for a host,
// and nothing else. Every field is read from a certificate nebula verified when the
// tunnel came up, or from our own, which is what lets a program on this host make an
// authorization decision from it, within two limits. The address must be inside this
// node's own networks: nebula drops an inbound packet whose source address is not in
// the sender's certificate, and one with a source in our networks that arrived through
// a peer's unsafe network rather than from the node holding it, so for a connection
// that arrived on the nebula interface from such an address the source is the sender's
// and this is the sender's identity. An address in an overlay network this node does
// not hold has no such guarantee: a packet claiming it is dropped from its holder but
// passes through another peer's unsafe network, so identity never answers for one,
// even with a tunnel to its holder up. And a connection that arrived on any other
// interface with an overlay source address was never checked by nebula at all, so a
// program authorizing on this answer should confirm the connection came in on the
// nebula interface. The field names are an API: the info API serves this shape to
// programs that were not built against nebula.
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

// runIdentity answers for whoever owns the address: this node, when it is one of ours or
// no address was given, or the peer behind an established tunnel. The address is an
// operand, as print-cert takes it. An address that is present and empty is a caller
// that failed to fill it in, and is refused rather than answered with this node's
// identity, which it could mistake for its peer's. With -pem the answer is the
// certificate the identity would have been read from, and nothing else.
func runIdentity(ifce *Interface, args *identityFlags, a []string) (commands.Result, error) {
	if len(a) > 1 {
		return commands.Failed("identity takes one vpn addr: identity [-pem] [<vpn addr>[:port]]"), nil
	}

	var addr string
	if len(a) == 1 {
		addr = a[0]
	}
	crt, fingerprint, err := lookupIdentity(ifce, addr, len(a) == 1)
	if err != nil {
		return commands.Failed("%s", err), nil
	}

	if args.Pem {
		b, err := crt.MarshalPEM()
		if err != nil {
			return commands.Failed("Unable to marshal the certificate: %s", err), nil
		}
		return commands.Value(certPEM{PEM: string(b)}), nil
	}

	id, err := newHostIdentity(crt, fingerprint)
	if err != nil {
		return commands.Result{}, err
	}

	return commands.Value(id), nil
}

// lookupIdentity is where identity's surfaces meet: the command and the info API both
// resolve an address, or none, to a certificate through it, so they cannot disagree
// about whose address it is. given says whether an address was passed at all: none is
// this node, while one that is empty is a caller's mistake and fails to parse. The
// error is a *lookupError, whose kind tells a surface with status codes whether the
// thing asked about was not there or the asking was wrong.
func lookupIdentity(ifce *Interface, addr string, given bool) (crt cert.Certificate, fingerprint string, err error) {
	cs := ifce.pki.getCertState()
	if !given {
		if crt = ownCertificate(cs); crt == nil {
			return nil, "", &lookupError{kind: lookupNoCertificate, msg: "No certificate is loaded"}
		}
		return crt, "", nil
	}

	vpnAddr, perr := parseVpnAddrWithOptionalPort(addr)
	if perr != nil {
		return nil, "", &lookupError{kind: lookupBadAddress, msg: "The provided vpn addr could not be parsed: " + addr}
	}
	if crt, fingerprint = findCertificateForVpnAddr(cs, ifce.hostMap, vpnAddr); crt == nil {
		return nil, "", &lookupError{kind: lookupNoTunnel, msg: "No active tunnel for vpn addr: " + vpnAddr.String()}
	}
	return crt, fingerprint, nil
}

// lookupError is why lookupIdentity found no certificate, in words for the asker and a
// kind for the surface.
type lookupError struct {
	kind lookupFailure
	msg  string
}

func (e *lookupError) Error() string { return e.msg }

type lookupFailure int

const (
	// lookupBadAddress: the address did not parse; the asking was wrong.
	lookupBadAddress lookupFailure = iota
	// lookupNoTunnel: no established tunnel is behind the address, or it is in a network
	// this node does not hold; the thing asked about is not there.
	lookupNoTunnel
	// lookupNoCertificate: this node has no certificate loaded, which a running nebula
	// never has; the fault is nobody's who asked.
	lookupNoCertificate
)

// textIdentityValue renders what identity reports for a person: the identity, or with
// -pem the certificate block alone, as print-cert -raw prints it.
func textIdentityValue(v any, w io.Writer) error {
	switch x := v.(type) {
	case hostIdentity:
		return textIdentity(x, w)
	case certPEM:
		_, err := io.WriteString(w, x.PEM)
		return err
	default:
		return fmt.Errorf("expected an identity, got %T", v)
	}
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

// ownCertificate is this node's certificate: the v2 one when it is loaded, else the v1.
// A v2 certificate is a superset of the v1 and may carry more networks, and it is the
// one newCertState builds myVpnAddrsTable from, so an address that matched that table is
// always listed in the certificate reported here. It is nil only when no certificate is
// loaded, which a running nebula never has.
func ownCertificate(cs *CertState) cert.Certificate {
	if cs == nil {
		return nil
	}
	if crt := cs.getCertificate(cert.Version2); crt != nil {
		return crt
	}
	return cs.getCertificate(cert.Version1)
}

// findCertificateForVpnAddr answers who owns a vpn address: this node, from its own
// certificate state, since the hostmap never carries an entry for ourselves, or the peer
// behind an established tunnel, for an address inside this node's own networks. The
// hostmap also indexes a peer under its addresses in networks this node does not hold,
// but a packet from such an address is dropped when its holder sends it and passes
// when another peer's unsafe network covers it, so naming the holder would name the
// wrong node; see hostIdentity. The certificate is nil for an address outside our
// networks, when the address is unknown, when the tunnel is still pending and when it
// is mid teardown. A peer's comes with the fingerprint nebula computed when it verified
// the certificate; our own comes with "", since none is kept for it. identity goes
// through it. The lighthouse's DNS TXT lookup goes through the two halves
// without the networks limit, since a TXT record describes a certificate rather than
// vouching for a sender, and keeps answering with the certificate handshakes start with.
func findCertificateForVpnAddr(cs *CertState, hostMap *HostMap, ip netip.Addr) (crt cert.Certificate, fingerprint string) {
	if ownsVpnAddr(cs, ip) {
		return ownCertificate(cs), ""
	}
	if !inOwnNetworks(cs, ip) {
		return nil, ""
	}
	return peerCertificateForVpnAddr(hostMap, ip)
}

// ownsVpnAddr reports whether ip is one of this node's own vpn addresses.
func ownsVpnAddr(cs *CertState, ip netip.Addr) bool {
	return cs != nil && cs.myVpnAddrsTable != nil && cs.myVpnAddrsTable.Contains(ip)
}

// inOwnNetworks reports whether ip is inside one of this node's own networks.
func inOwnNetworks(cs *CertState, ip netip.Addr) bool {
	return cs != nil && cs.myVpnNetworksTable != nil && cs.myVpnNetworksTable.Contains(ip)
}

// peerCertificateForVpnAddr is the certificate of the peer behind an established tunnel
// to ip, with the fingerprint nebula computed when it verified it, or nil when there is
// no such tunnel. See findCertificateForVpnAddr.
func peerCertificateForVpnAddr(hostMap *HostMap, ip netip.Addr) (crt cert.Certificate, fingerprint string) {
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
