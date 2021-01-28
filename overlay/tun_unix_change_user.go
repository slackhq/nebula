//go:build !android && !ios && !e2e_testing
// +build !android,!ios,!e2e_testing

package overlay

import (
	"syscall"
	"fmt"
	"strconv"
	"os"
	"os/user"

	"github.com/sirupsen/logrus"
)

func ChangeToUser(l *logrus.Logger, changeToUser string) error {
	var account *user.User
	var err error

	if len(changeToUser) == 0 {
		return nil
	}

	if account, err = user.Lookup(changeToUser); err != nil {
		return fmt.Errorf("could not find user %v: %s", changeToUser, err)
	}

	uid, err := strconv.ParseInt(account.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("could not parse account UID %v: %s", account.Uid, err)
	}
	gid, err := strconv.ParseInt(account.Gid, 10, 32)
	if err != nil {
		return fmt.Errorf("could not parse account GID %v: %s", account.Gid, err)
	}

	groups, err := account.GroupIds()
	if err != nil {
		return fmt.Errorf("could not get groups for UID %v: %s", account.Uid, err)
	}

	gids := make([]int, len(groups))
	for idx, gidstr := range groups {
		accountGid, err := strconv.ParseInt(gidstr, 10, 32)
		if err != nil {
			return fmt.Errorf("could not parse GID %v: %s", gidstr, err)
		}
		gids[idx] = int(accountGid)
	}

	l.Infof("Dropping privileges to %v (UID %v, GID %v)", account.Username, uid, gid)

	err = syscall.Setgroups(gids)
	if err != nil {
		return fmt.Errorf("could not set groups for %v: %s", changeToUser, err)
	}

	err = syscall.Setgid(int(gid))
	if err != nil {
		return fmt.Errorf("could not set GID to %v: %s", gid, err)
	}

	err = syscall.Setuid(int(uid))
	if err != nil {
		return fmt.Errorf("could not set UID to %v: %s", uid, err)
	}

	actualUid := int64(os.Geteuid())
	actualGid := int64(os.Getegid())

	if actualUid != uid || actualGid != gid {
		return fmt.Errorf("expected to be running as %v (%v:%v); actually %v:%v", account.Username, uid, gid, actualUid, actualGid)
	} else {
        l.Infof("Now running as %v", account.Username)
	}

	return nil
}
