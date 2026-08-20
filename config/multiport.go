package config

type MultiPortConfig struct {
	Tx               bool
	Rx               bool
	TxBasePort       uint16
	TxPorts          int
	TxHandshake      bool
	TxHandshakeDelay int64
}
