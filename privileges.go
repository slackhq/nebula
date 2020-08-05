// +build !windows

package nebula

import (
	"fmt"
	"os/user"
)

func privileged() (bool, error) {
	u, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("check user: %w", err)
	}

	return u.Uid == "0", nil
}
