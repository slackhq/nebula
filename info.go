package nebula

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

func handleHostmapList(l *logrus.Logger, hm *HostMap, w http.ResponseWriter, r *http.Request) {
	type HostListItem struct {
		VpnAddrs []netip.Addr `json:"vpnAddrs"`
		//Remote            netip.AddrPort `json:"remote"`
		Relayed           bool      `json:"relayed,omitempty"`
		LastHandshakeTime time.Time `json:"lastHandshakeTime"`
		Groups            []string  `json:"groups"`
	}

	out := map[string]HostListItem{}
	hm.ForEachVpnAddr(func(hi *HostInfo) {
		cert := hi.GetCert().Certificate
		out[cert.Name()] = HostListItem{
			VpnAddrs: hi.vpnAddrs,
			//Remote:            hi.remote,
			Relayed:           !hi.remote.IsValid(),
			LastHandshakeTime: time.Unix(0, int64(hi.lastHandshakeTime)),
			Groups:            cert.Groups(),
		}
	})

	w.Header().Set("Content-Type", "application/json")
	js := json.NewEncoder(w)
	err := js.Encode(out)
	if err != nil {
		http.Error(w, "json error: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleHostCertLookup(l *logrus.Logger, hm *HostMap, w http.ResponseWriter, r *http.Request) {
	ipStr := r.PathValue("ipStr")
	if ipStr == "" {
		http.Error(w, "you must provide an IP address", http.StatusNotFound)
		return
	}

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		//todo filter non-Nebula IPs?
		http.Error(w, fmt.Sprintf("Invalid IP address: %s", ipStr), http.StatusBadRequest)
		return
	}
	hi := hm.QueryVpnAddr(addr)
	if hi == nil {
		http.Error(w, "IP address not found", http.StatusNotFound)
		return
	} else if hi.ConnectionState == nil {
		http.Error(w, "Host not connected", http.StatusNotFound)
		return
	}
	out, err := hi.ConnectionState.peerCert.Certificate.MarshalJSON()
	if err != nil {
		l.WithError(err).Error("failed to marshal peer certificate")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func setupInfoServer(l *logrus.Logger, hm *HostMap) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hostmap", func(w http.ResponseWriter, r *http.Request) { handleHostmapList(l, hm, w, r) })
	mux.HandleFunc("GET /host/{ipStr}", func(w http.ResponseWriter, r *http.Request) { handleHostCertLookup(l, hm, w, r) })
	return mux
}

// startInfo stands up a REST API that serves information about what Nebula is doing to other services
// Right now, this is just hostmap info,
func startInfo(l *logrus.Logger, c *config.C, configTest bool, hm *HostMap) (func(), error) {
	listen := c.GetString("info.listen", "") //todo this should probably refuse non-localhost, right?
	if listen == "" {
		return nil, nil
	}

	var startFn func()
	if configTest {
		return startFn, nil
	}

	startFn = func() {
		mux := setupInfoServer(l, hm)
		l.WithField("bind", listen).Info("Info listener starting")
		err := http.ListenAndServe(listen, mux)
		if errors.Is(err, http.ErrServerClosed) {
			return
		}
		if err != nil {
			l.Fatal(err)
		}
	}

	return startFn, nil
}
