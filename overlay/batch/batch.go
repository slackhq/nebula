package batch

// SortKey identifies a packet's position in its sender's transmission order.
// Epoch is a receiver-local ordinal for the tunnel (ConnectionState) that decrypted the packet:
// a re-handshake replaces the tunnel outright and the replacement's epoch is higher,
// so the old tunnel's packets sort first during the cutover overlap.
// Counter is the packet's AEAD message counter within that tunnel.
type SortKey struct {
	Epoch   uint64
	Counter uint64
}
