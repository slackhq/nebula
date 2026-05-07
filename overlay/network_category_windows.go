//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// networkCategory mirrors NLM_NETWORK_CATEGORY from netlistmgr.h.
type networkCategory int32

const (
	networkCategoryPublic              networkCategory = 0
	networkCategoryPrivate             networkCategory = 1
	networkCategoryDomainAuthenticated networkCategory = 2
)

func (c networkCategory) String() string {
	switch c {
	case networkCategoryPublic:
		return "public"
	case networkCategoryPrivate:
		return "private"
	case networkCategoryDomainAuthenticated:
		return "domain"
	}
	return fmt.Sprintf("unknown(%d)", c)
}

// parseNetworkCategory accepts the user-supplied tun.network_category. A
// second return of false means "leave the category alone".
func parseNetworkCategory(s string) (networkCategory, bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "unset":
		return 0, false, nil
	case "public":
		return networkCategoryPublic, true, nil
	case "private":
		return networkCategoryPrivate, true, nil
	case "domain", "domainauthenticated":
		return networkCategoryDomainAuthenticated, true, nil
	}
	return 0, false, fmt.Errorf("unknown tun.network_category %q (expected public, private, domain, or unset)", s)
}

// CLSID_NetworkListManager {DCB00C01-570F-4A9B-8D69-199FDBA5723B}
var clsidNetworkListManager = windows.GUID{
	Data1: 0xDCB00C01, Data2: 0x570F, Data3: 0x4A9B,
	Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B},
}

// IID_INetworkListManager {DCB00000-570F-4A9B-8D69-199FDBA5723B}
var iidINetworkListManager = windows.GUID{
	Data1: 0xDCB00000, Data2: 0x570F, Data3: 0x4A9B,
	Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B},
}

// x/sys/windows doesn't expose CoCreateInstance, so we bind it ourselves.
var procCoCreateInstance = windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateInstance")

const clsCtxAll = windows.CLSCTX_INPROC_SERVER | windows.CLSCTX_INPROC_HANDLER |
	windows.CLSCTX_LOCAL_SERVER | windows.CLSCTX_REMOTE_SERVER

const (
	hrSFALSE          = 0x00000001
	hrRPCEChangedMode = 0x80010106
)

type hresult uint32

func (h hresult) failed() bool { return int32(h) < 0 }
func (h hresult) String() string {
	return fmt.Sprintf("HRESULT 0x%08x", uint32(h))
}

var errAdapterNotFound = errors.New("adapter not present in network connections enumeration")

// Vtable layouts. Slot order must match the declaration order in netlistmgr.h.
// All NLM interfaces here derive from IDispatch, which derives from IUnknown.

type iUnknownVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
}

type iDispatchVtbl struct {
	iUnknownVtbl
	GetTypeInfoCount uintptr
	GetTypeInfo      uintptr
	GetIDsOfNames    uintptr
	Invoke           uintptr
}

type iNetworkListManagerVtbl struct {
	iDispatchVtbl
	GetNetworks           uintptr
	GetNetwork            uintptr
	GetNetworkConnections uintptr
	GetNetworkConnection  uintptr
	IsConnectedToInternet uintptr
	IsConnected           uintptr
	GetConnectivity       uintptr
}

type iNetworkListManager struct{ Vtbl *iNetworkListManagerVtbl }

func (n *iNetworkListManager) Release() {
	syscall.SyscallN(n.Vtbl.Release, uintptr(unsafe.Pointer(n)))
}

func (n *iNetworkListManager) GetNetworkConnections() (*iEnumNetworkConnections, error) {
	var enum *iEnumNetworkConnections
	r1, _, _ := syscall.SyscallN(n.Vtbl.GetNetworkConnections,
		uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&enum)),
	)
	if hr := hresult(r1); hr.failed() {
		return nil, fmt.Errorf("INetworkListManager.GetNetworkConnections: %s", hr)
	}
	return enum, nil
}

type iEnumNetworkConnectionsVtbl struct {
	iDispatchVtbl
	NewEnum uintptr
	Next    uintptr
	Skip    uintptr
	Reset   uintptr
	Clone   uintptr
}

type iEnumNetworkConnections struct{ Vtbl *iEnumNetworkConnectionsVtbl }

func (e *iEnumNetworkConnections) Release() {
	syscall.SyscallN(e.Vtbl.Release, uintptr(unsafe.Pointer(e)))
}

// Next returns the next connection, or (nil, nil) at the end of the enumeration.
func (e *iEnumNetworkConnections) Next() (*iNetworkConnection, error) {
	var conn *iNetworkConnection
	var fetched uint32
	r1, _, _ := syscall.SyscallN(e.Vtbl.Next,
		uintptr(unsafe.Pointer(e)), 1,
		uintptr(unsafe.Pointer(&conn)), uintptr(unsafe.Pointer(&fetched)),
	)
	if hr := hresult(r1); hr.failed() {
		return nil, fmt.Errorf("IEnumNetworkConnections.Next: %s", hr)
	}
	if fetched == 0 {
		return nil, nil
	}
	return conn, nil
}

type iNetworkConnectionVtbl struct {
	iDispatchVtbl
	GetNetwork            uintptr
	IsConnectedToInternet uintptr
	IsConnected           uintptr
	GetConnectivity       uintptr
	GetConnectionId       uintptr
	GetAdapterId          uintptr
	GetDomainType         uintptr
}

type iNetworkConnection struct{ Vtbl *iNetworkConnectionVtbl }

func (c *iNetworkConnection) Release() {
	syscall.SyscallN(c.Vtbl.Release, uintptr(unsafe.Pointer(c)))
}

func (c *iNetworkConnection) GetAdapterId() (windows.GUID, error) {
	var g windows.GUID
	r1, _, _ := syscall.SyscallN(c.Vtbl.GetAdapterId,
		uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(&g)),
	)
	if hr := hresult(r1); hr.failed() {
		return windows.GUID{}, fmt.Errorf("INetworkConnection.GetAdapterId: %s", hr)
	}
	return g, nil
}

func (c *iNetworkConnection) GetNetwork() (*iNetwork, error) {
	var net *iNetwork
	r1, _, _ := syscall.SyscallN(c.Vtbl.GetNetwork,
		uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(&net)),
	)
	if hr := hresult(r1); hr.failed() {
		return nil, fmt.Errorf("INetworkConnection.GetNetwork: %s", hr)
	}
	return net, nil
}

type iNetworkVtbl struct {
	iDispatchVtbl
	GetName                    uintptr
	SetName                    uintptr
	GetDescription             uintptr
	SetDescription             uintptr
	GetNetworkId               uintptr
	GetDomainType              uintptr
	GetNetworkConnections      uintptr
	GetTimeCreatedAndConnected uintptr
	IsConnectedToInternet      uintptr
	IsConnected                uintptr
	GetConnectivity            uintptr
	GetCategory                uintptr
	SetCategory                uintptr
}

type iNetwork struct{ Vtbl *iNetworkVtbl }

func (n *iNetwork) Release() {
	syscall.SyscallN(n.Vtbl.Release, uintptr(unsafe.Pointer(n)))
}

func (n *iNetwork) GetCategory() (networkCategory, error) {
	var c networkCategory
	r1, _, _ := syscall.SyscallN(n.Vtbl.GetCategory,
		uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&c)),
	)
	if hr := hresult(r1); hr.failed() {
		return 0, fmt.Errorf("INetwork.GetCategory: %s", hr)
	}
	return c, nil
}

func (n *iNetwork) SetCategory(c networkCategory) error {
	r1, _, _ := syscall.SyscallN(n.Vtbl.SetCategory,
		uintptr(unsafe.Pointer(n)), uintptr(int32(c)),
	)
	if hr := hresult(r1); hr.failed() {
		return fmt.Errorf("INetwork.SetCategory: %s", hr)
	}
	return nil
}

// coInit initializes COM for the current OS thread. The returned function must
// be deferred to balance a successful init. RPC_E_CHANGED_MODE means COM is
// already initialized in a different mode on this thread, which is still fine
// for our calls but we must not Uninitialize in that case.
func coInit() (func(), error) {
	err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED)
	if err == nil {
		return windows.CoUninitialize, nil
	}
	if e, ok := err.(syscall.Errno); ok {
		switch uint32(e) {
		case hrSFALSE:
			return windows.CoUninitialize, nil
		case hrRPCEChangedMode:
			return func() {}, nil
		}
	}
	return nil, fmt.Errorf("CoInitializeEx: %w", err)
}

func createNetworkListManager() (*iNetworkListManager, error) {
	var nlm *iNetworkListManager
	r1, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidNetworkListManager)),
		0,
		uintptr(clsCtxAll),
		uintptr(unsafe.Pointer(&iidINetworkListManager)),
		uintptr(unsafe.Pointer(&nlm)),
	)
	if hr := hresult(r1); hr.failed() {
		return nil, fmt.Errorf("CoCreateInstance(NetworkListManager): %s", hr)
	}
	return nlm, nil
}

// setNetworkCategory locates the network connection bound to adapterGUID and
// sets the category of its parent network. Returns errAdapterNotFound if the
// adapter is not yet visible in the NLM enumeration.
func setNetworkCategory(adapterGUID windows.GUID, cat networkCategory) error {
	deinit, err := coInit()
	if err != nil {
		return err
	}
	defer deinit()

	nlm, err := createNetworkListManager()
	if err != nil {
		return err
	}
	defer nlm.Release()

	enum, err := nlm.GetNetworkConnections()
	if err != nil {
		return err
	}
	defer enum.Release()

	for {
		conn, err := enum.Next()
		if err != nil {
			return err
		}
		if conn == nil {
			return errAdapterNotFound
		}

		guid, err := conn.GetAdapterId()
		if err != nil || guid != adapterGUID {
			conn.Release()
			continue
		}

		net, err := conn.GetNetwork()
		conn.Release()
		if err != nil {
			return err
		}
		err = net.SetCategory(cat)
		net.Release()
		return err
	}
}

// applyNetworkCategory polls until the wintun adapter shows up in the NLM
// enumeration, then sets the category. Intended to run in its own goroutine.
func applyNetworkCategory(l *slog.Logger, adapterGUID windows.GUID, cat networkCategory) {
	// COM Init/Uninit must be paired on the same OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	const (
		attempts = 30
		interval = 500 * time.Millisecond
	)
	for i := 0; i < attempts; i++ {
		err := setNetworkCategory(adapterGUID, cat)
		if err == nil {
			l.Info("Set Windows network category", "category", cat.String())
			return
		}
		if !errors.Is(err, errAdapterNotFound) {
			l.Warn("Failed to set Windows network category", "error", err, "category", cat.String())
			return
		}
		time.Sleep(interval)
	}
	l.Warn("Gave up waiting for adapter to appear in NLM enumeration; network category not set",
		"category", cat.String(),
		"waited", time.Duration(attempts)*interval,
	)
}
