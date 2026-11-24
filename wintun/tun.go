//go:build windows
// +build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

//NOTE: This file was forked from https://git.zx2c4.com/wireguard-go/tree/tun/tun_windows.go?id=851efb1bb65555e0f765a3361c8eb5ac47435b19
// Mainly to shed functionality we won't be using and to fix names that display in the system

package wintun

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wintun"
)

const (
	ringCapacity = 0x800000 // Ring capacity, 8 MiB

	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)
	spinloopRateThreshold      = 800000000 / 8                                   // 800mbps
	spinloopDuration           = uint64(time.Millisecond / 80 / time.Nanosecond) // ~1gbit/s
)

// ErrSendRingCorrupt is returned when Wintun reports ERROR_INVALID_DATA on the
// send ring and in-process session recovery either failed or tripped its rate limit.
var ErrSendRingCorrupt = errors.New("Send ring corrupt")

// startRetryDelays bounds retries when WintunStartSession transiently returns
// ERROR_ALREADY_EXISTS right after WintunEndSession.
var startRetryDelays = []time.Duration{
	5 * time.Millisecond,
	15 * time.Millisecond,
	30 * time.Millisecond,
}

type rateJuggler struct {
	current       atomic.Uint64
	nextByteCount atomic.Uint64
	nextStartTime atomic.Int64
	changing      atomic.Int32
}

type NativeTun struct {
	wt         *wintun.Adapter
	name       string
	handle     windows.Handle
	rate       rateJuggler
	sessionMu  sync.RWMutex
	session    wintun.Session
	readWait   windows.Handle
	hasSession bool
	closed     bool
	fatalErr   error
	limiter    resetLimiter
	resetCount atomic.Uint64
	onReset    func(resets uint64)
	waiting    sync.WaitGroup
	closeOnce  sync.Once
	closedAtom atomic.Bool
}

var WintunTunnelType = "Nebula"
var WintunStaticRequestedGUID *windows.GUID

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

// CreateTUN creates a Wintun interface with the given name. Should a Wintun
// interface with the same name exist, it is reused.
func CreateTUN(ifname string, mtu int) (Device, error) {
	return CreateTUNWithRequestedGUID(ifname, WintunStaticRequestedGUID, mtu)
}

// CreateTUNWithRequestedGUID creates a Wintun interface with the given name and
// a requested GUID. Should a Wintun interface with the same name exist, it is reused.
func CreateTUNWithRequestedGUID(ifname string, requestedGUID *windows.GUID, mtu int) (Device, error) {
	wt, err := wintun.CreateAdapter(ifname, WintunTunnelType, requestedGUID)
	if err != nil {
		return nil, fmt.Errorf("Error creating interface: %w", err)
	}

	tun := &NativeTun{
		wt:      wt,
		name:    ifname,
		handle:  windows.InvalidHandle,
		limiter: newResetLimiter(defaultMaxSessionResets, defaultSessionResetWindow, time.Now),
	}

	tun.session, err = wt.StartSession(ringCapacity)
	if err != nil {
		tun.wt.Close()
		return nil, fmt.Errorf("Error starting session: %w", err)
	}
	tun.readWait = tun.session.ReadWaitEvent()
	tun.hasSession = true
	return tun, nil
}

// SetOnSessionReset registers a callback invoked after the Wintun session is
// restarted in-process to recover from a corrupted send ring. The callback runs
// synchronously on the Read goroutine and must not block or call Read.
func (tun *NativeTun) SetOnSessionReset(fn func(resets uint64)) {
	tun.sessionMu.Lock()
	tun.onReset = fn
	tun.sessionMu.Unlock()
}

func (tun *NativeTun) Name() (string, error) {
	return tun.name, nil
}

func (tun *NativeTun) File() *os.File {
	return nil
}

func (tun *NativeTun) Close() error {
	tun.closeOnce.Do(func() {
		tun.closedAtom.Store(true)

		tun.sessionMu.Lock()
		tun.closed = true
		if tun.hasSession {
			windows.SetEvent(tun.readWait)
		}
		tun.sessionMu.Unlock()

		tun.waiting.Wait()

		tun.sessionMu.Lock()
		if tun.hasSession {
			tun.session.End()
			tun.session = wintun.Session{}
			tun.readWait = 0
			tun.hasSession = false
		}
		if tun.wt != nil {
			tun.wt.Close()
			tun.wt = nil
		}
		tun.sessionMu.Unlock()
	})
	return nil
}

// Note: Read() assumes the caller comes only from a single goroutine.

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
retry:
	if tun.closedAtom.Load() {
		return 0, os.ErrClosed
	}
	start := nanotime()
	shouldSpin := tun.rate.current.Load() >= spinloopRateThreshold && uint64(start-tun.rate.nextStartTime.Load()) <= rateMeasurementGranularity*2

	tun.sessionMu.RLock()
	if tun.closed {
		tun.sessionMu.RUnlock()
		return 0, os.ErrClosed
	}
	if tun.fatalErr != nil {
		err := tun.fatalErr
		tun.sessionMu.RUnlock()
		return 0, err
	}
	if !tun.hasSession {
		tun.sessionMu.RUnlock()
		return 0, os.ErrClosed
	}
	sess := tun.session
	readWait := tun.readWait
	for {
		if tun.closedAtom.Load() {
			tun.sessionMu.RUnlock()
			return 0, os.ErrClosed
		}
		packet, err := sess.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			copy(buff[offset:], packet)
			sess.ReleaseReceivePacket(packet)
			tun.sessionMu.RUnlock()
			tun.rate.update(uint64(packetSize))
			return packetSize, nil
		case windows.ERROR_NO_MORE_ITEMS:
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				tun.waiting.Add(1)
				tun.sessionMu.RUnlock()
				windows.WaitForSingleObject(readWait, windows.INFINITE)
				tun.waiting.Done()
				goto retry
			}
			procyield(1)
			continue
		case windows.ERROR_HANDLE_EOF:
			tun.sessionMu.RUnlock()
			return 0, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			tun.sessionMu.RUnlock()
			if rerr := tun.recoverCorruptSession(); rerr != nil {
				return 0, rerr
			}
			goto retry
		}
		tun.sessionMu.RUnlock()
		return 0, fmt.Errorf("Read failed: %w", err)
	}
}

// recoverCorruptSession replaces the active Wintun session in-process.
// Must only be called from the single Read goroutine.
func (tun *NativeTun) recoverCorruptSession() error {
	tun.sessionMu.Lock()
	if tun.closed {
		tun.sessionMu.Unlock()
		return os.ErrClosed
	}
	if tun.fatalErr != nil {
		err := tun.fatalErr
		tun.sessionMu.Unlock()
		return err
	}
	if !tun.hasSession {
		tun.sessionMu.Unlock()
		return os.ErrClosed
	}

	tun.session.End()
	tun.session = wintun.Session{}
	tun.readWait = 0
	tun.hasSession = false

	if !tun.limiter.allow() {
		err := fmt.Errorf("%w (exceeded %d session resets in %s)", ErrSendRingCorrupt, tun.limiter.maxResets, tun.limiter.window)
		tun.fatalErr = err
		tun.sessionMu.Unlock()
		return err
	}

	var (
		sess wintun.Session
		err  error
	)
	for attempt := 0; ; attempt++ {
		if tun.closedAtom.Load() {
			tun.sessionMu.Unlock()
			return os.ErrClosed
		}
		sess, err = tun.wt.StartSession(ringCapacity)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) || attempt >= len(startRetryDelays) {
			fatal := fmt.Errorf("%w (session restart failed: %w)", ErrSendRingCorrupt, err)
			tun.fatalErr = fatal
			tun.sessionMu.Unlock()
			return fatal
		}
		time.Sleep(startRetryDelays[attempt])
	}

	tun.session = sess
	tun.readWait = sess.ReadWaitEvent()
	tun.hasSession = true
	resets := tun.resetCount.Add(1)
	cb := tun.onReset
	tun.sessionMu.Unlock()

	if cb != nil {
		cb(resets)
	}
	return nil
}

func (tun *NativeTun) Flush() error {
	return nil
}

func (tun *NativeTun) Write(buff []byte, offset int) (int, error) {
	tun.sessionMu.RLock()
	if tun.closed {
		tun.sessionMu.RUnlock()
		return 0, os.ErrClosed
	}
	if tun.fatalErr != nil {
		err := tun.fatalErr
		tun.sessionMu.RUnlock()
		return 0, err
	}
	if !tun.hasSession {
		tun.sessionMu.RUnlock()
		return 0, os.ErrClosed
	}

	packetSize := len(buff) - offset
	packet, err := tun.session.AllocateSendPacket(packetSize)
	if err == nil {
		copy(packet, buff[offset:])
		tun.session.SendPacket(packet)
		tun.sessionMu.RUnlock()
		tun.rate.update(uint64(packetSize))
		return packetSize, nil
	}
	tun.sessionMu.RUnlock()

	switch err {
	case windows.ERROR_HANDLE_EOF:
		return 0, os.ErrClosed
	case windows.ERROR_BUFFER_OVERFLOW:
		return 0, nil // Dropping when ring is full.
	}
	return 0, fmt.Errorf("Write failed: %w", err)
}

// LUID returns Windows interface instance ID.
func (tun *NativeTun) LUID() uint64 {
	tun.sessionMu.RLock()
	defer tun.sessionMu.RUnlock()
	if tun.closed || tun.wt == nil {
		return 0
	}
	return tun.wt.LUID()
}

// RunningVersion returns the running version of the Wintun driver.
func (tun *NativeTun) RunningVersion() (version uint32, err error) {
	return wintun.RunningVersion()
}

func (rate *rateJuggler) update(packetLen uint64) {
	now := nanotime()
	total := rate.nextByteCount.Add(packetLen)
	period := uint64(now - rate.nextStartTime.Load())
	if period >= rateMeasurementGranularity {
		if !rate.changing.CompareAndSwap(0, 1) {
			return
		}
		rate.nextStartTime.Store(now)
		rate.current.Store(total * uint64(time.Second/time.Nanosecond) / period)
		rate.nextByteCount.Store(0)
		rate.changing.Store(0)
	}
}
