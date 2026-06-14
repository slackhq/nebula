package nebula

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/pq"
	"github.com/slackhq/nebula/sshd"
)

// pqStatusRow is one peer's line in pq-status output.
type pqStatusRow struct {
	VpnAddr     string `json:"vpnAddr"`
	CertName    string `json:"certName"`
	Subtype     string `json:"subtype"`
	PSK         bool   `json:"pskPresent"`
	PrevEpoch   bool   `json:"prevEpochRetained"`
	Binding     string `json:"binding"` // ok | mismatch | cert-only | hint-only | none
	Msg2Rejects uint64 `json:"ixpsk2Msg2Rejects,omitempty"`
	Timeouts    uint64 `json:"ixpsk2Timeouts,omitempty"`
	// DegradeEpisodes is the cumulative count of IXPSK2->IXPSK0 strip
	// windows for this peer. SURVIVES recovery: non-zero here means the
	// link was downgraded at least once (persistent desync or active
	// downgrade attack) even if it is back on IXPSK2 now.
	DegradeEpisodes uint64 `json:"ixpsk2DegradeEpisodes,omitempty"`
}

// pqBindingVerdict classifies the live agreement between a peer's
// CA-signed binding extension and the local provider's binding hint.
func pqBindingVerdict(certHash, rpHash string) string {
	switch {
	case certHash != "" && rpHash != "" && certHash == rpHash:
		return "ok"
	case certHash != "" && rpHash != "":
		return "mismatch"
	case certHash != "":
		return "cert-only"
	case rpHash != "":
		return "hint-only"
	default:
		return "none"
	}
}

func sshPQStatus(f *Interface, flags *sshListHostMapFlags, w sshd.StringWriter) error {
	provider := f.pki.PQProvider()
	stats := f.handshakeManager.PQPeerStats()

	var rows []pqStatusRow
	f.hostMap.RLock()
	for addr, hi := range f.hostMap.Hosts {
		row := pqStatusRow{VpnAddr: addr.String()}
		var peerCert cert.Certificate
		if c := hi.GetCert(); c != nil {
			peerCert = c.Certificate
			row.CertName = peerCert.Name()
		}
		if cs := hi.ConnectionState; cs != nil {
			row.Subtype = header.SubTypeName(header.Handshake, cs.subtype)
		}
		if peerCert != nil && pq.HasPSK(provider) {
			pub := peerCert.PublicKey()
			psk, rpHash, ok := provider.LookupWithBinding(pub)
			row.PSK = ok
			pq.Wipe(psk)
			if prev, _, pok := pq.LookupPrevious(provider, pub); pok {
				row.PrevEpoch = true
				pq.Wipe(prev)
			}
			row.Binding = pqBindingVerdict(certHashHex(peerCert), rpHash)
		} else {
			row.Binding = "none"
		}
		if st, ok := stats[addr]; ok {
			row.Msg2Rejects = st.Msg2Rejects
			row.Timeouts = st.Timeouts
			row.DegradeEpisodes = st.DegradeEpisodes
		}
		rows = append(rows, row)
	}
	f.hostMap.RUnlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].VpnAddr < rows[j].VpnAddr })

	if flags.Json || flags.Pretty {
		out := struct {
			Providers []pq.ProviderStatus `json:"providers"`
			Peers     []pqStatusRow       `json:"peers"`
		}{pq.Status(provider), rows}
		js := json.NewEncoder(w.GetWriter())
		if flags.Pretty {
			js.SetIndent("", "    ")
		}
		return js.Encode(out)
	}

	for _, r := range rows {
		if err := w.WriteLine(fmt.Sprintf(
			"%s  name=%s subtype=%s psk=%v prev=%v binding=%s rejects=%d timeouts=%d degrades=%d",
			r.VpnAddr, r.CertName, r.Subtype, r.PSK, r.PrevEpoch, r.Binding, r.Msg2Rejects, r.Timeouts, r.DegradeEpisodes)); err != nil {
			return err
		}
	}
	return nil
}
