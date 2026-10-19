//go:build windows

package localapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// pipePrefix is where windows named pipes live. The pipe's own security descriptor
// carries the access control that the socket's mode carries on unix.
const pipePrefix = `\\.\pipe\`

// protectedPrefix is the pipe namespace that only administrators and SYSTEM may create
// names under; the kernel refuses everyone else. The default name lives there, so the
// name itself says who could have created the pipe answering it: no ordinary user can
// have put anything under it ahead of the daemon. Tailscale, WireGuard and NetBird keep
// their daemon pipes there for the same reason. nebula on windows is already an
// administrator, since creating the tun adapter requires it.
const protectedPrefix = pipePrefix + `ProtectedPrefix\Administrators\`

const network = "pipe"

// currentUID is the identity the unix owner checks are made for. There is no uid here
// and no per-connection check that would read one, so the value is never consulted; it
// exists so a Server is built the same way on every platform.
var currentUID = func() uint32 { return 0 }

// logListening is the line written when the pipe is up. It says which layer is doing
// the access control, so nobody assumes a per-connection check that is not running:
// there is none here, the pipe's security descriptor admits only the accounts listed in
// ownerOnlySDDL, and the kernel enforces that at connect time.
func logListening(l *slog.Logger, path string) {
	l.Info("Local control socket listening, access restricted by the pipe's security descriptor",
		"path", path,
		"reason", "the security descriptor built at listen time is the access check; the connecting process is not identified separately",
	)
}

// listen creates the named pipe at path with a security descriptor that admits only the
// user nebula runs as, SYSTEM and Administrators.
//
// The first instance is created, never opened, so a name some other process already
// holds is refused rather than joined: that process would otherwise answer clients in
// nebula's place. Under protectedPrefix only an administrator could hold it; anywhere
// else any account could. Either way the refusal is reported as errEndpointHeld for the
// caller to log as the event it is, except when the refusal is the namespace's own: a
// daemon that is not an administrator cannot create under protectedPrefix at all, and
// that is told apart so the operator is sent to elevate or to name a pipe elsewhere
// rather than to look for a process that is not there.
func listen(path string) (net.Listener, error) {
	sddl, err := ownerOnlySDDL()
	if err != nil {
		return nil, fmt.Errorf("could not build a security descriptor for %s: %w", path, err)
	}

	ln, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    int32(MaxRequestBytes),
		OutputBufferSize:   64 * 1024,
	})
	if err != nil {
		return nil, listenRefused(path, isAdministrator(), err)
	}

	return ln, nil
}

// listenRefused turns a failure to create the pipe at path into the error the caller
// logs. admin says whether this process may create under protectedPrefix.
//
// ERROR_ACCESS_DENIED is ambiguous: it is what the kernel says to a non-administrator
// creating under protectedPrefix, and also what an existing instance whose DACL does
// not admit us says to a second create. A process that is an administrator cannot be
// getting the first, so for it, and for every name outside the prefix, access denied
// means held.
func listenRefused(path string, admin bool, err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) && isProtectedPath(path) && !admin {
		return fmt.Errorf("creating %s requires an administrator, as only administrators may create pipes under %s; run nebula elevated, or set %s to a pipe name outside it: %w", path, protectedPrefix, CtlSocketKey, err)
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("%w: %s: %w", errEndpointHeld, path, err)
	}
	return err
}

// isProtectedPath says whether path is a name under protectedPrefix. Pipe names are
// case insensitive, so the comparison is too.
func isProtectedPath(path string) bool {
	return len(path) > len(protectedPrefix) && strings.EqualFold(path[:len(protectedPrefix)], protectedPrefix)
}

// isAdministrator says whether this process holds Administrators as an enabled group,
// which is what creating under protectedPrefix takes. SYSTEM holds it; an elevated
// administrator holds it; an administrator's unelevated token carries it deny-only,
// which the membership check correctly reads as no. The membership is checked against
// the thread's own token: CheckTokenMembership wants an impersonation token and makes
// one from the primary token when handed none. A check that cannot be made is read as
// not an administrator, which only changes the wording of a failure that has already
// happened.
func isAdministrator() bool {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	member, err := windows.Token(0).IsMember(admins)
	return err == nil && member
}

// ownerOnlySDDL grants full access to the account nebula is running as, to SYSTEM and
// to Administrators, and to nobody else. P makes the DACL protected, so it does not
// inherit entries that would widen it.
//
// Administrators is the counterpart of the uid 0 allowance in the unix peer check. The
// service normally runs as LocalSystem, so without it an operator in an elevated shell
// could not reach the daemon at all; and an administrator can already stop the service,
// so this grants no authority they did not have.
func ownerOnlySDDL() (string, error) {
	token := windows.GetCurrentProcessToken()

	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}

	sid := user.User.Sid.String()
	return fmt.Sprintf("D:P(A;;GA;;;%s)(A;;GA;;;SY)(A;;GA;;;BA)", sid), nil
}

// removeSocket is a no-op: a named pipe disappears when its last handle closes, so
// there is nothing to unlink and no stale instance to clean up.
func removeSocket(path string) {}

// dial connects to the pipe and, before the connection carries anything, checks who
// serves it. The request names a command and its arguments, so it must not reach a
// pipe that some other account put under nebula's name. For the default name the
// namespace already promises that, since only an administrator could have created it;
// the check is what covers a CtlSocketKey override outside protectedPrefix, and costs
// nothing to make on every name.
func dial(path string, timeout time.Duration) (net.Conn, error) {
	conn, err := winio.DialPipe(path, &timeout)
	if err != nil {
		return nil, err
	}

	if err := checkPipeOwner(conn, path); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// checkPipeOwner refuses a pipe whose owner is not an account that could be running
// nebula. It is the unix owner check made from the other side: the handle winio dialed
// exposes the pipe object, and the object's owner is whoever created it.
//
// The owner is what makes this sound. An account can only create an object owned by
// itself, or by a SID it holds with the owner flag, unless it has SeRestorePrivilege,
// which ordinary users do not; so a pipe owned by SYSTEM, Administrators or a service
// account was put there by one of them, and never by a user squatting the name. winio
// dials with SECURITY_ANONYMOUS, so the impostor could not have impersonated the client
// either, but it could have read the command and answered it with whatever it liked.
func checkPipeOwner(conn net.Conn, path string) error {
	h, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("%s: cannot identify who serves the pipe", path)
	}

	sd, err := windows.GetSecurityInfo(windows.Handle(h.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: could not read the pipe's owner: %w", path, err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%s: could not read the pipe's owner: %w", path, err)
	}
	if owner == nil {
		return fmt.Errorf("%s has no owner; refusing to send to it", path)
	}

	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("%s: could not read own identity: %w", path, err)
	}

	if ownerAccepted(owner, me.User.Sid) {
		return nil
	}

	return fmt.Errorf("%s is served by %s, not by nebula; run nebula ctl as that user, or pass -config or -socket to name the daemon's pipe", path, describeSID(owner))
}

// ownerAccepted says whether a pipe owned by owner may be sent a request by a client
// running as me: the client's own account, and the two accounts a daemon runs under
// that no ordinary user can create an object as, SYSTEM and Administrators. Another
// account is refused, whoever the client is; the daemon's DACL decides who may connect,
// and this decides who may answer.
func ownerAccepted(owner, me *windows.SID) bool {
	return owner.Equals(me) ||
		owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

// describeSID renders a SID with its account name when the host can say what it is, so
// a message about somebody else's pipe tells the operator who that is.
func describeSID(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}

// defaultSocketPath is the control pipe when the config names none. It is under
// protectedPrefix, so whatever answers it was created by an administrator or SYSTEM; see
// there.
const defaultSocketPath = protectedPrefix + "nebula-ctl"

// checkSocketPath refuses a configured name that is not a full pipe name. A pipe lives
// under pipePrefix and nowhere else, so a bare name has no meaning here, and one under
// pipePrefix is used as given. An override outside protectedPrefix is a name any
// account could have created first; the owner check in dial is what protects a client
// of one.
func checkSocketPath(key, value string) error {
	if len(value) <= len(pipePrefix) || !strings.EqualFold(value[:len(pipePrefix)], pipePrefix) {
		return fmt.Errorf(`%s must be a full pipe name under %s, got %q`, key, pipePrefix, value)
	}
	return nil
}
