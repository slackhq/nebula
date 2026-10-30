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
	// EncryptQueues, above 1, gives every tunnel that many send ciphers, one per routine, when the cipher needs a lock
	// around encryption (FIPS 140 and boringcrypto). Each routine then encrypts under its own lock instead of every
	// routine sharing one per tunnel.
	EncryptQueues int
}
