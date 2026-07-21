//go:build !darwin || ios || e2e_testing
// +build !darwin ios e2e_testing

package udp

import (
	"context"
	"log/slog"
)

// watchNetworkChanges is a no-op outside of darwin.
//
// Darwin is the platform that scopes a udp socket to the interface it came up on, so it is the platform whose socket
// goes stale when the local network changes. Everywhere else Rebind has nothing to do, so there is nothing to watch
// for. iOS is excluded on purpose even though it is darwin: the host app already drives the rebind off NWPathMonitor,
// and two things racing to rebind the same socket is worse than one.
//
// A nil channel means "not supported here", which callers must treat as "do not start a watcher" rather than
// selecting on it, since a receive from a nil channel blocks forever.
func watchNetworkChanges(_ context.Context, _ *slog.Logger) (<-chan struct{}, error) {
	return nil, nil
}
