package commands

// Name identifies a command. Every command nebula serves is a constant here, so a
// surface, a client and a test spell it the same way and are told at compile time when
// they do not. It is a string rather than an integer so a test can register a throwaway
// command without adding it here, and so the wire carries the name as the string it has
// always been.
type Name string

const (
	ChangeRemote          Name = "change-remote"
	CloseTunnel           Name = "close-tunnel"
	CreateTunnel          Name = "create-tunnel"
	DeviceInfo            Name = "device-info"
	Help                  Name = "help"
	Identity              Name = "identity"
	ListHostmap           Name = "list-hostmap"
	ListLighthouseAddrmap Name = "list-lighthouse-addrmap"
	ListPendingHostmap    Name = "list-pending-hostmap"
	LogFormat             Name = "log-format"
	LogLevel              Name = "log-level"
	Logout                Name = "logout"
	PrintCert             Name = "print-cert"
	PrintRelays           Name = "print-relays"
	PrintTunnel           Name = "print-tunnel"
	QueryLighthouse       Name = "query-lighthouse"
	Reload                Name = "reload"
	Version               Name = "version"
)
