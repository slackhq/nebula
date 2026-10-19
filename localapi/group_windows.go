//go:build windows

package localapi

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// lookupGroupID resolves an account name, local or domain qualified, or a SID written
// out, to the SID as a string, which is how the pipe's security descriptor names it.
// Any account the host can resolve is accepted, as docker accepts any SID for its -G: a
// group is the natural thing to name, but the descriptor does not care.
func lookupGroupID(name string) (string, error) {
	if strings.HasPrefix(strings.ToUpper(name), "S-1-") {
		sid, err := windows.StringToSid(name)
		if err != nil {
			return "", fmt.Errorf("%q is not a SID: %w", name, err)
		}
		return sid.String(), nil
	}

	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		return "", fmt.Errorf("account %q does not exist on this host: %w", name, err)
	}
	return sid.String(), nil
}
