//go:build (amd64 || arm64) && !e2e_testing
// +build amd64 arm64
// +build !e2e_testing

// Package wfp installs Windows Filtering Platform (WFP) PERMIT filters in a dynamic, session-scoped sublayer.
// Because WFP sits below Windows Defender Firewall, a high-weight permit at FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6 lets
// the matching inbound traffic through regardless of WDF rules.
//
// Each Session owns its own engine handle. When the handle closes, every dynamic object added during the session
// is auto-deleted by Windows, so there are no orphaned filters.
//
// Type definitions and constants are derived from the wireguard-windows firewall package (MIT).
// Only the subset we exercise is reproduced.
package wfp

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FWPM layer GUIDs (fwpmu.h).
//
// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = e1cd9fe7-f4b5-4273-96c0-592e487b8650
// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = a3b42c97-9f04-4672-b87e-cee9c483257f
var (
	fwpmLayerAleAuthRecvAcceptV4 = windows.GUID{
		Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273,
		Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50},
	}
	fwpmLayerAleAuthRecvAcceptV6 = windows.GUID{
		Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672,
		Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f},
	}
)

// FWPM_CONDITION_IP_LOCAL_INTERFACE = 4cd62a49-59c3-4969-b7f3-bda5d32890a4
var fwpmConditionIPLocalInterface = windows.GUID{
	Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969,
	Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4},
}

// FWPM_CONDITION_IP_PROTOCOL = 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7
var fwpmConditionIPProtocol = windows.GUID{
	Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a,
	Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7},
}

// FWPM_CONDITION_IP_LOCAL_PORT = 0c1ba1af-5765-453f-af22-a8f791ac775b
var fwpmConditionIPLocalPort = windows.GUID{
	Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f,
	Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b},
}

// IPPROTO_UDP from in.h.
const ipprotoUDP uint8 = 17

// FWP_ACTION_TYPE values (fwptypes.h). PERMIT is terminating.
const fwpActionPermit uint32 = 0x00001002 // 0x2 | FWP_ACTION_FLAG_TERMINATING(0x1000)

// FWP_DATA_TYPE values we use.
const (
	fwpEmpty  uint32 = 0
	fwpUint8  uint32 = 1
	fwpUint16 uint32 = 2
	fwpUint64 uint32 = 4
)

// FWP_MATCH_TYPE values.
const fwpMatchEqual uint32 = 0

// FWPM_SESSION flags.
const fwpmSessionFlagDynamic uint32 = 0x1

// FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT prevents lower-priority filters in other sublayers,
// notably Windows Defender Firewall's MPSSVC_WF sublayer, which shares our 0xFFFF weight from overriding this PERMIT.
// Without it, a default WDF block at the same sublayer weight can still win arbitration.
const fwpmFilterFlagClearActionRight uint32 = 0x8

// RPC authentication.
// RPC_C_AUTHN_WINNT works on workgroup machines with no domain context
// RPC_C_AUTHN_DEFAULT falls back through a chain that can land on something WFP doesn't accept on a fresh box.
const rpcCAuthnWinNT uint32 = 10

// fwpByteBlob (FWP_BYTE_BLOB). 16 bytes on 64-bit.
type fwpByteBlob struct {
	size uint32
	_    uint32 // padding
	data *uint8
}

// fwpValue0 / FWP_CONDITION_VALUE0 layout. 16 bytes on 64-bit.
// The union is pointer-sized; types <= 32 bits (UINT8/16/32, INT8/16/32, float) live inline in the low bytes
// of `value`, while UINT64/INT64/double and aggregate types are stored *by pointer*, even on 64-bit, where the
// union member is declared as UINT64*. So when populating an FWP_UINT64 condition, pass
// uintptr(unsafe.Pointer(&luidVar)) instead of the LUID inline.
type fwpValue0 struct {
	type_ uint32
	_     uint32 // padding before union to 8-byte alignment
	value uintptr
}

// fwpmDisplayData0 / FWPM_DISPLAY_DATA0. 16 bytes on 64-bit.
type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

// fwpmAction0 / FWPM_ACTION0. 20 bytes; no leading padding because actionType
// is uint32 and GUID's first field is uint32.
type fwpmAction0 struct {
	actionType uint32
	filterType windows.GUID
}

// fwpmFilterCondition0. 40 bytes on 64-bit.
type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID // 16
	matchType      uint32       // 4
	_              uint32       // 4 padding
	conditionValue fwpValue0    // 16
}

// fwpmFilter0. 200 bytes on 64-bit.
type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	_                   uint32 // padding before *GUID
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	_                   uint32 // padding before pointer
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_                   [4]byte // layout correction
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

// fwpmSublayer0. 72 bytes on 64-bit.
type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	_            uint32 // padding before *GUID
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
	_            [6]byte // padding to 72 bytes
}

// fwpmSession0. 72 bytes on 64-bit.
type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processId            uint32
	_                    uint32 // padding before *SID
	sid                  *windows.SID
	username             *uint16
	kernelMode           uint8
	_                    [7]byte // tail padding
}

// fwpuclnt.dll bindings. Only the calls we use.
var (
	modFwpuclnt          = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0  = modFwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0 = modFwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0 = modFwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0   = modFwpuclnt.NewProc("FwpmFilterAdd0")
)

// Session holds the WFP engine handle for a single bypass operation. The handle owns a dynamic session:
// when it is closed, every WFP object added during the session (sublayer + filters) is automatically deleted by
// Windows. That gives us correct cleanup even if the host process is killed hard between Permit* and Close.
type Session struct {
	engine uintptr
}

// Close releases the engine handle. Windows deletes every dynamic object (sublayer + filters) the session installed.
// Safe to call on a nil receiver.
func (s *Session) Close() {
	if s == nil || s.engine == 0 {
		return
	}
	procFwpmEngineClose0.Call(s.engine)
	s.engine = 0
}

// PermitInterface installs PERMIT filters at FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 and _V6 scoped to the given network
// interface LUID. Inbound traffic on that interface bypasses Windows Defender Firewall.
func PermitInterface(luid uint64) (*Session, error) {
	s, sublayerKey, err := newSession()
	if err != nil {
		return nil, err
	}

	if err := addInterfaceFilter(s.engine, sublayerKey, fwpmLayerAleAuthRecvAcceptV4, luid); err != nil {
		s.Close()
		return nil, fmt.Errorf("add v4 filter: %w", err)
	}
	if err := addInterfaceFilter(s.engine, sublayerKey, fwpmLayerAleAuthRecvAcceptV6, luid); err != nil {
		s.Close()
		return nil, fmt.Errorf("add v6 filter: %w", err)
	}
	return s, nil
}

// PermitUDPPort installs PERMIT filters at FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 and _V6 scoped to UDP traffic with the
// given local port. Inbound UDP to that port on any interface bypasses Windows Defender Firewall.
func PermitUDPPort(port uint16) (*Session, error) {
	s, sublayerKey, err := newSession()
	if err != nil {
		return nil, err
	}

	if err := addUDPPortFilter(s.engine, sublayerKey, fwpmLayerAleAuthRecvAcceptV4, port); err != nil {
		s.Close()
		return nil, fmt.Errorf("add v4 filter: %w", err)
	}
	if err := addUDPPortFilter(s.engine, sublayerKey, fwpmLayerAleAuthRecvAcceptV6, port); err != nil {
		s.Close()
		return nil, fmt.Errorf("add v6 filter: %w", err)
	}
	return s, nil
}

func newSession() (*Session, windows.GUID, error) {
	engine, err := openDynamicEngine()
	if err != nil {
		return nil, windows.GUID{}, err
	}
	sublayerKey, err := registerSublayer(engine)
	if err != nil {
		procFwpmEngineClose0.Call(engine)
		return nil, windows.GUID{}, err
	}
	return &Session{engine: engine}, sublayerKey, nil
}

func openDynamicEngine() (uintptr, error) {
	session := fwpmSession0{flags: fwpmSessionFlagDynamic}
	var engine uintptr
	r1, _, _ := procFwpmEngineOpen0.Call(
		0, // serverName == NULL (local)
		uintptr(rpcCAuthnWinNT),
		0, // authIdentity == NULL
		uintptr(unsafe.Pointer(&session)),
		uintptr(unsafe.Pointer(&engine)),
	)
	if r1 != 0 {
		return 0, fmt.Errorf("FwpmEngineOpen0: 0x%x", r1)
	}
	return engine, nil
}

// registerSublayer adds a session-scoped sublayer with a freshly generated GUID, weight 0xFFFF so its filters arbitrate
// above WDF's default sublayer. The sublayer is dynamic (no PERSISTENT flag) and goes away when the engine handle closes.
func registerSublayer(engine uintptr) (windows.GUID, error) {
	key, err := windows.GenerateGUID()
	if err != nil {
		return windows.GUID{}, fmt.Errorf("GenerateGUID for sublayer: %w", err)
	}

	name, _ := windows.UTF16PtrFromString("Nebula WDF bypass sublayer")
	desc, _ := windows.UTF16PtrFromString("Permit filters bypassing Windows Defender Firewall")
	sl := fwpmSublayer0{
		subLayerKey: key,
		displayData: fwpmDisplayData0{name: name, description: desc},
		weight:      0xFFFF,
	}
	r1, _, _ := procFwpmSubLayerAdd0.Call(
		engine,
		uintptr(unsafe.Pointer(&sl)),
		0, // sd == NULL
	)
	if r1 != 0 {
		return windows.GUID{}, fmt.Errorf("FwpmSubLayerAdd0: 0x%x", r1)
	}
	return key, nil
}

func addInterfaceFilter(engine uintptr, sublayerKey, layer windows.GUID, luid uint64) error {
	name, _ := windows.UTF16PtrFromString("Nebula allow interface inbound")
	desc, _ := windows.UTF16PtrFromString("Permits inbound traffic on a nebula interface")

	// luid must remain addressable through the syscall -- FWP_UINT64 is stored
	// by pointer in the FWP_VALUE0 union.
	cond := fwpmFilterCondition0{
		fieldKey:  fwpmConditionIPLocalInterface,
		matchType: fwpMatchEqual,
		conditionValue: fwpValue0{
			type_: fwpUint64,
			value: uintptr(unsafe.Pointer(&luid)),
		},
	}

	filter := fwpmFilter0{
		// filterKey left zero: WFP assigns one when the filter is added.
		displayData:         fwpmDisplayData0{name: name, description: desc},
		flags:               fwpmFilterFlagClearActionRight,
		layerKey:            layer,
		subLayerKey:         sublayerKey,
		weight:              fwpValue0{type_: fwpUint8, value: uintptr(15)},
		numFilterConditions: 1,
		filterCondition:     &cond,
		action:              fwpmAction0{actionType: fwpActionPermit},
	}

	r1, _, _ := procFwpmFilterAdd0.Call(
		engine,
		uintptr(unsafe.Pointer(&filter)),
		0, // sd == NULL
		0, // id == NULL
	)
	if r1 != 0 {
		return fmt.Errorf("FwpmFilterAdd0: 0x%x", r1)
	}
	return nil
}

// addUDPPortFilter installs a PERMIT filter that matches (IP_PROTOCOL == UDP) AND (IP_LOCAL_PORT == port).
// FWP_UINT8 and FWP_UINT16 are <= 32 bits so they live inline in the FWP_VALUE0 union.
func addUDPPortFilter(engine uintptr, sublayerKey, layer windows.GUID, port uint16) error {
	name, _ := windows.UTF16PtrFromString("Nebula allow UDP port inbound")
	desc, _ := windows.UTF16PtrFromString("Permits inbound UDP to a nebula listener port")

	conds := [2]fwpmFilterCondition0{
		{
			fieldKey:  fwpmConditionIPProtocol,
			matchType: fwpMatchEqual,
			conditionValue: fwpValue0{
				type_: fwpUint8,
				value: uintptr(ipprotoUDP),
			},
		},
		{
			fieldKey:  fwpmConditionIPLocalPort,
			matchType: fwpMatchEqual,
			conditionValue: fwpValue0{
				type_: fwpUint16,
				value: uintptr(port),
			},
		},
	}

	filter := fwpmFilter0{
		displayData:         fwpmDisplayData0{name: name, description: desc},
		flags:               fwpmFilterFlagClearActionRight,
		layerKey:            layer,
		subLayerKey:         sublayerKey,
		weight:              fwpValue0{type_: fwpUint8, value: uintptr(15)},
		numFilterConditions: 2,
		filterCondition:     &conds[0],
		action:              fwpmAction0{actionType: fwpActionPermit},
	}

	r1, _, _ := procFwpmFilterAdd0.Call(
		engine,
		uintptr(unsafe.Pointer(&filter)),
		0,
		0,
	)
	if r1 != 0 {
		return fmt.Errorf("FwpmFilterAdd0: 0x%x", r1)
	}
	return nil
}
