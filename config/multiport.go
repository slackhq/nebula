package config

type MultiPortConfig struct {
	Tx               bool
	Rx               bool
	TxBasePort       uint16
	TxPorts          int
	TxHandshake      bool
	TxHandshakeDelay int64
	// ReplayWindow is the replay window length for every tunnel. Multiport spreads one tunnel's packets over every
	// queue on both hosts, so they arrive further out of order than one flow on one queue.
	ReplayWindow uint64
}
