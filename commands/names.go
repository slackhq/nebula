package commands

import "slices"

// Name identifies a command.
//
// The set is closed: every command nebula serves is a constant here and listed in Known,
// and TestKnownNamesAreTheRegisteredSet in the root package holds what is registered to
// that list. Which of them a daemon registers is decided by its configuration, not at
// run time, so a surface, a client and a test can all spell a command the same way and
// be told at compile time when they do not.
//
// The type is a string rather than an integer so a test can register a throwaway command
// without adding it here, and so the wire and the schema carry the name as the string
// it has always been. Such a name is listed after the Known ones; see Registry.All.
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
	MutexProfileFraction  Name = "mutex-profile-fraction"
	PrintCert             Name = "print-cert"
	PrintRelays           Name = "print-relays"
	PrintTunnel           Name = "print-tunnel"
	QueryLighthouse       Name = "query-lighthouse"
	Reload                Name = "reload"
	SaveHeapProfile       Name = "save-heap-profile"
	SaveMutexProfile      Name = "save-mutex-profile"
	StartCPUProfile       Name = "start-cpu-profile"
	StopCPUProfile        Name = "stop-cpu-profile"
	Version               Name = "version"
)

// Known is every command, in display order: help lists them and the schema describes
// them in this order, on every surface. It is alphabetical today, which is the order
// both always had; reorder it and the goldens show exactly what moved.
var Known = [...]Name{
	ChangeRemote,
	CloseTunnel,
	CreateTunnel,
	DeviceInfo,
	Help,
	Identity,
	ListHostmap,
	ListLighthouseAddrmap,
	ListPendingHostmap,
	LogFormat,
	LogLevel,
	Logout,
	MutexProfileFraction,
	PrintCert,
	PrintRelays,
	PrintTunnel,
	QueryLighthouse,
	Reload,
	SaveHeapProfile,
	SaveMutexProfile,
	StartCPUProfile,
	StopCPUProfile,
	Version,
}

// IsKnown reports whether n is one of nebula's commands, whether or not any registry
// holds it.
func (n Name) IsKnown() bool {
	return slices.Contains(Known[:], n)
}
