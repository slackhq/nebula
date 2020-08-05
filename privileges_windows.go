package nebula

import (
	"fmt"
	"log"

	"golang.org/x/sys/windows"
)

// This windows magic brought to you by https://github.com/golang/go/issues/28804
func privileged() (bool, error) {
	var sid *windows.SID

	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		log.Fatalf("SID Error: %s", err)
		return false, fmt.Errorf("SID error: %w", err)
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	admin, err := token.IsMember(sid)
	if err != nil {
		return false, fmt.Errorf("token membership: %w", err)
	}

	return admin, nil
}
