package nebula

import (
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func Test_ixHandshake(t *testing.T) {
	var err error

	// Build up boilerplate
	ca, _, caKey, caPEM := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	trustedCAs, err = cert.NewCAPoolFromBytes(caPEM)
	assert.NoError(t, err)
	defMask := net.IPMask{0, 0, 0, 0}

	myAddr := &udpAddr{IP: net.ParseIP("10.1.1.1"), Port: 4200}
	myIpNet := &net.IPNet{IP: net.IP{1, 2, 3, 4}, Mask: defMask}
	myVpnIp := ip2int(myIpNet.IP)
	myCert, _, myPrivKey := newTestCert(ca, caKey, "me", time.Now(), time.Now().Add(5*time.Minute), myIpNet, nil, []string{})

	theirAddr := &udpAddr{IP: net.ParseIP("10.1.1.2"), Port: 4200}
	theirIpNet := &net.IPNet{IP: net.IP{4, 3, 2, 1}, Mask: defMask}
	theirVpnIp := ip2int(theirIpNet.IP)
	theirCert, _, theirPrivKey := newTestCert(ca, caKey, "them", time.Now(), time.Now().Add(5*time.Minute), theirIpNet, nil, []string{})

	evilAddr := &udpAddr{IP: net.ParseIP("10.9.9.9"), Port: 4200}
	evilIpNet := &net.IPNet{IP: net.IP{9, 9, 9, 9}, Mask: defMask}
	evilVpnIp := ip2int(evilIpNet.IP)
	evilCert, _, evilPrivKey := newTestCert(ca, caKey, "evil", time.Now(), time.Now().Add(5*time.Minute), evilIpNet, nil, []string{})

	// Test a well behaving handshake between 2 parties
	t.Run("well behaved", func(t *testing.T) {
		myF := newTestInterface(t, myCert, myPrivKey)
		theirF := newTestInterface(t, theirCert, theirPrivKey)

		theirHi := myF.handshakeManager.pendingHostMap.AddVpnIP(theirVpnIp)
		theirHi.ConnectionState = myF.newConnectionState(true, noise.HandshakeIX, []byte{}, 0)

		// I start a handshake
		ixHandshakeStage0(myF, theirVpnIp, theirHi)

		// Make sure my pending hostmap is correct
		assert.Equal(t, theirHi, myF.handshakeManager.pendingHostMap.Indexes[theirHi.localIndexId])
		assert.Equal(t, theirHi, myF.handshakeManager.pendingHostMap.Hosts[theirHi.hostId])
		assert.Empty(t, myF.handshakeManager.pendingHostMap.RemoteIndexes)

		// They consume that and send me back the final handshake. They should have a tunnel now
		stage1 := make([]byte, 0, mtu)
		ixHandshakeStage1(theirF, myAddr, theirHi.HandshakePacket[0], &Header{}, newTestWriter(&stage1, nil))

		// I consume the final handshake, I should have a tunnel now
		assert.False(t, ixHandshakeStage2(myF, theirAddr, theirHi, stage1, &Header{}))

		// Make sure host maps look right
		assertHostMapEntries(t, myF.hostMap, theirHi)
		assertHostMapSize(t, theirF.hostMap, 1)

		// Lets see if it works
		assertHostMapPair(t, myF.hostMap, theirF.hostMap, myVpnIp, theirVpnIp, myAddr, theirAddr)
		testTunnel(t, myF, theirF, myVpnIp, theirVpnIp)

		// Make sure their pending hostmap is empty
		assert.Empty(t, theirF.handshakeManager.pendingHostMap.Indexes)
		assert.Empty(t, theirF.handshakeManager.pendingHostMap.Hosts)
		assert.Empty(t, theirF.handshakeManager.pendingHostMap.RemoteIndexes)

		//NOTE: my pending hostmap is cleaned up outside of the current test path by the handshake manager
	})

	// Make sure we ignore multiple stage 2 handshakes
	//TODO: waiting on https://github.com/flynn/noise/pull/39
	//t.Run("multiple stage 2 received", func(t *testing.T) {
	//	myF := newTestInterface(t, myCert, myPrivKey)
	//	theirF := newTestInterface(t, theirCert, theirPrivKey)
	//
	//	theirHi := myF.handshakeManager.pendingHostMap.AddVpnIP(theirVpnIp)
	//	theirHi.ConnectionState = myF.newConnectionState(true, noise.HandshakeIX, []byte{}, 0)
	//
	//	// Get up to stage 2
	//	ixHandshakeStage0(myF, theirVpnIp, theirHi)
	//
	//	stage1 := make([]byte, 0, mtu)
	//	ixHandshakeStage1(theirF, myAddr, theirHi.HandshakePacket[0], &Header{}, newTestWriter(&stage1, nil))
	//
	//	// I will eat multiple stage 1 packets, duplicated or not
	//	assert.False(t, ixHandshakeStage2(myF, theirAddr, theirHi, append(stage1, 3), &Header{}))              // junk: added garbage
	//	assert.False(t, ixHandshakeStage2(myF, theirAddr, theirHi, stage1[HeaderLen+20:], &Header{}))          // junk: missing the start
	//	assert.False(t, ixHandshakeStage2(myF, theirAddr, theirHi, stage1[:len(stage1)-HeaderLen], &Header{})) // junk: missing the end
	//	assert.False(t, ixHandshakeStage2(myF, theirAddr, theirHi, stage1, &Header{}))                         // good
	//
	//	//assert.False(t, ixHandshakeStage2(myF, theirAddr, theirHi, stage1, &Header{})) // duplicate good
	//
	//	// Lets see if it works
	//	assertHostMapPair(t, myF.hostMap, theirF.hostMap, myVpnIp, theirVpnIp, myAddr, theirAddr)
	//	testTunnel(t, myF, theirF, myVpnIp, theirVpnIp)
	//})

	t.Run("bad stage 0 bytes", func(t *testing.T) {
		theirF := newTestInterface(t, theirCert, theirPrivKey)

		stage1 := make([]byte, 0, mtu)
		ixHandshakeStage1(theirF, myAddr, []byte("this is nonsense"), &Header{}, newTestWriter(&stage1, nil))

		//TODO: the side effect is a log statement but we can check other things like my pending hostmap and their hostmap
		assert.Empty(t, stage1)
	})

	//TODO: stage 0 events
	//TODO: impossible today, no index generated
	//TODO: impossible today, proto did not marshal
	//TODO: noise WriteMessage fails, likely due to already completed tunnel but stuck in pending hostmap. Likely tested at a higher level
	//TODO: race (both sides are initiators and responders)

	//TODO: stage 1 events
	//TODO: noise ReadMessage fails, stage 1 should be idempotent, not sure how this happens
	//TODO: impossible today, proto did not unmarshal
	//TODO: invalid cert
	//TODO: handshake with self
	//TODO: impossible today, no index generated
	//TODO: impossible today, proto did not marshal
	//TODO: noise WriteMessage fails, likely due to already completed tunnel but we generate hostinfo here, not sure how this works
	//TODO: race (received multiple same stage 0 packets)
	//TODO: race (received multiple different stage 0 packets)
	//TODO: impossible today, duplicate index generated

	//TODO: stage 2 events
	//TODO: nil hostinfo, what even?
	//TODO: race - attack (received multiple same stage 1 packets)
	//TODO: noise ReadMessage fails, likely a race but we lock
	//TODO: noise ReadMessage does not arrive at keys, no idea
	//TODO: impossible today, proto did not marshal
	//TODO: invalid cert
	//TODO: wrong responder
	//TODO: race - attack (received multiple different stage 1 packets)

	t.Run("wrong responder", func(t *testing.T) {
		myF := newTestInterface(t, myCert, myPrivKey)
		theirF := newTestInterface(t, theirCert, theirPrivKey)
		evilF := newTestInterface(t, evilCert, evilPrivKey)

		// I am trying to reach theirVpnIp
		myF.lightHouse.AddRemote(theirVpnIp, evilAddr, false)
		myF.lightHouse.AddRemote(theirVpnIp, theirAddr, false)

		// Generate our stage 0
		evilHi := myF.getOrHandshake(theirVpnIp)

		//TODO: add a pending entry for evil to make sure it gets cleaned up
		// Make sure we are going to use the evil address
		myF.handshakeManager.pendingHostMap.AddVpnIP(evilVpnIp)
		assert.Equal(t, evilHi.Remotes[0], evilAddr, "Our host info for them should have the evil addr")
		assert.Contains(t, myF.lightHouse.QueryCache(theirVpnIp), evilAddr, "Our lighthouse should have the evil addr for their vpn ip")

		// Add some cached packets to make sure they get moved
		evilHi.cachePacket(message, 0, []byte("cached packet 1"), func(t NebulaMessageType, st NebulaMessageSubType, h *HostInfo, p, nb, out []byte) {})

		// But the wrong host received the stage 0
		stage1 := make([]byte, mtu)
		ixHandshakeStage1(evilF, myAddr, evilHi.HandshakePacket[0], &Header{}, newTestWriter(&stage1, nil))
		assert.False(t, ixHandshakeStage2(myF, evilAddr, evilHi, stage1, &Header{}), "Our stage 2 failed unexpectedly")

		// We should have a working tunnel with evil now
		assert.Empty(t, evilHi.packetStore, "Our cached packets should have been removed")
		assertHostMapPair(t, myF.hostMap, evilF.hostMap, myVpnIp, evilVpnIp, myAddr, evilAddr)
		testTunnel(t, myF, evilF, myVpnIp, evilVpnIp)

		// I should have a new host info for them now
		theirHi, _ := myF.handshakeManager.pendingHostMap.QueryVpnIP(theirVpnIp)
		assert.NotEqual(t, theirHi.localIndexId, evilHi.localIndexId, "New host info has the same local as the old one")
		assert.Len(t, theirHi.packetStore, 1, "our cached packet should have moved to the new host info")
		assert.Equal(t, theirHi.packetStore[0].packet, []byte("cached packet 1"), "Our cached packet was wrong")

		// Ensure I got rid of the evil udp addr
		assert.Len(t, theirHi.Remotes, 1, "Our new host info should only have 1 entry")
		assert.Equal(t, theirAddr, theirHi.Remotes[0], "Our new host info Remotes should have their good udp addr")

		stage1 = make([]byte, mtu)
		ixHandshakeStage1(theirF, myAddr, theirHi.HandshakePacket[0], &Header{}, newTestWriter(&stage1, nil))
		assert.False(t, ixHandshakeStage2(myF, theirAddr, theirHi, stage1, &Header{}), "Our stage 2 failed unexpectedly")

		// Make sure my hostmap looks good
		assert.Len(t, myF.handshakeManager.pendingHostMap.Hosts, 1)
		assert.Len(t, myF.handshakeManager.pendingHostMap.Indexes, 1)
		for _, v := range myF.handshakeManager.pendingHostMap.Hosts {
			t.Log(IntIp(v.hostId))
		}
		assertHostMapEntries(t, myF.hostMap, evilHi, theirHi)

		// Make sure evil and their hostmap is the correct size
		assertHostMapSize(t, theirF.hostMap, 1)
		assertHostMapSize(t, evilF.hostMap, 1)

		// Test with them
		assertHostMapPair(t, myF.hostMap, theirF.hostMap, myVpnIp, theirVpnIp, myAddr, theirAddr)
		testTunnel(t, myF, theirF, myVpnIp, theirVpnIp)

		// Make sure evil is still good
		assertHostMapPair(t, myF.hostMap, evilF.hostMap, myVpnIp, evilVpnIp, myAddr, evilAddr)
		testTunnel(t, myF, evilF, myVpnIp, evilVpnIp)
	})

	t.Run("many wrong responders", func(t *testing.T) {
		myF := newTestInterface(t, myCert, myPrivKey)
		theirF := newTestInterface(t, theirCert, theirPrivKey)
		evilF := newTestInterface(t, evilCert, evilPrivKey)

		// I am trying to reach theirVpnIp
		evilAddrs := []*udpAddr{
			{IP: net.ParseIP("10.9.9.9"), Port: 4201},
			{IP: net.ParseIP("10.9.9.9"), Port: 4202},
			{IP: net.ParseIP("10.9.9.9"), Port: 4203},
			{IP: net.ParseIP("10.9.9.9"), Port: 4204},
			{IP: net.ParseIP("10.9.9.9"), Port: 4205},
			{IP: net.ParseIP("10.9.9.9"), Port: 4206},
			{IP: net.ParseIP("10.9.9.9"), Port: 4207},
			{IP: net.ParseIP("10.9.9.9"), Port: 4208},
			{IP: net.ParseIP("10.9.9.9"), Port: 4209},
			{IP: net.ParseIP("10.9.9.9"), Port: 4210},
			{IP: net.ParseIP("10.9.9.9"), Port: 4211},
			theirAddr,
		}
		myF.lightHouse.AddRemote(theirVpnIp, evilAddrs[0], false)
		myF.lightHouse.AddRemote(theirVpnIp, evilAddrs[1], false)
		myF.lightHouse.AddRemote(theirVpnIp, evilAddrs[2], false)
		myF.lightHouse.AddRemote(theirVpnIp, evilAddrs[3], false)
		myF.lightHouse.AddRemote(theirVpnIp, evilAddrs[4], false)
		myF.lightHouse.AddRemote(theirVpnIp, evilAddrs[5], false)
		myF.lightHouse.AddRemote(theirVpnIp, evilAddrs[6], false)
		myF.lightHouse.AddRemote(theirVpnIp, evilAddrs[6], false)

		var theirHi, evilHi *HostInfo
		for i := 0; i < len(evilAddrs); i++ {
			// Generate our stage 0
			evilHi = myF.getOrHandshake(theirVpnIp)
			t.Log("pre evil bads", evilHi.badRemotes)
			t.Log("pre evil remotes", evilHi.Remotes)
			//assert.Equal(t, evilHi.Remotes[0], evilAddr, "Our host info for them should have the evil addr")
			//TODO: make sure the lh has them all
			//assert.Contains(t, myF.lightHouse.QueryCache(theirVpnIp), evilAddr, "Our lighthouse should have the evil addr for their vpn ip")

			// But the wrong host received the stage 0
			stage1 := make([]byte, mtu)
			ixHandshakeStage1(evilF, myAddr, evilHi.HandshakePacket[0], &Header{}, newTestWriter(&stage1, nil))
			assert.False(t, ixHandshakeStage2(myF, evilAddrs[i], evilHi, stage1, &Header{}), "Our stage 2 failed unexpectedly")

			// We should have a working tunnel with evil now
			//assert.Empty(t, evilHi.packetStore, "Our cached packets should have been removed")
			//myHiInEvil, _ := assertHostMapPair(t, myF.hostMap, evilF.hostMap, myVpnIp, evilVpnIp, myAddr, evilAddr)
			//testTunnel(t, myF, evilF, myVpnIp, evilVpnIp)
			// Get rid of the tunnel in evilF so we can do the work again
			evilF.closeTunnel(evilF.getOrHandshake(myVpnIp)) //TODO: this seems wrong, should be the 2nd return

			// I should have a new host info for them now
			theirHi, _ = myF.handshakeManager.pendingHostMap.QueryVpnIP(theirVpnIp)
			assert.NotEqual(t, theirHi.localIndexId, evilHi.localIndexId, "New host info has the same local as the old one")

			//TODO: Ensure I got rid of the evil udp addr
			t.Log("post evil bads", evilHi.badRemotes)
			t.Log("post evil remotes", evilHi.Remotes)
			//assert.Len(t, theirHi.Remotes, 1, "Our new host info should only have 1 entry")
			//assert.Equal(t, theirAddr, theirHi.Remotes[0], "Our new host info Remotes should have their good udp addr")
		}

		stage1 := make([]byte, mtu)
		ixHandshakeStage1(theirF, myAddr, theirHi.HandshakePacket[0], &Header{}, newTestWriter(&stage1, nil))
		assert.False(t, ixHandshakeStage2(myF, theirAddr, theirHi, stage1, &Header{}), "Our stage 2 failed unexpectedly")

		// Make sure my hostmap looks good
		assert.Len(t, myF.handshakeManager.pendingHostMap.Hosts, 1)
		assert.Len(t, myF.handshakeManager.pendingHostMap.Indexes, 1)
		for _, v := range myF.handshakeManager.pendingHostMap.Hosts {
			t.Log(IntIp(v.hostId))
		}
		assertHostMapEntries(t, myF.hostMap, evilHi, theirHi)

		// Make sure evil and their hostmap is the correct size
		assertHostMapSize(t, theirF.hostMap, 1)
		assertHostMapSize(t, evilF.hostMap, 1)

		// Test with them
		assertHostMapPair(t, myF.hostMap, theirF.hostMap, myVpnIp, theirVpnIp, myAddr, theirAddr)
		testTunnel(t, myF, theirF, myVpnIp, theirVpnIp)

		// Make sure evil is still good
		assertHostMapPair(t, myF.hostMap, evilF.hostMap, myVpnIp, evilVpnIp, myAddr, evilAddr)
		testTunnel(t, myF, evilF, myVpnIp, evilVpnIp)

	})
	//TODO: test a big lie from lh (more than 10 evil ips)
}

func testTunnel(t *testing.T, fA, fB *Interface, vpnA, vpnB uint32) {
	plain := make([]byte, mtu)
	crypt := make([]byte, mtu)
	nonce := make([]byte, 12)

	// Get our host info objects
	hA, err := fA.hostMap.QueryVpnIP(vpnB)
	assert.NoError(t, err)
	assert.True(t, hA.HandshakeComplete)
	assert.True(t, hA.ConnectionState.ready)

	hB, err := fB.hostMap.QueryVpnIP(vpnA)
	assert.NoError(t, err)
	assert.True(t, hB.HandshakeComplete)
	assert.True(t, hB.ConnectionState.ready)

	// A encrypt for B
	crypt, err = hA.ConnectionState.eKey.EncryptDanger(crypt[:0], nil, []byte("hi from a"), 1, nonce)
	assert.NoError(t, err)
	assert.NotEqual(t, []byte("hi from a"), crypt)

	// B decrypt from A
	plain, err = hB.ConnectionState.dKey.DecryptDanger(plain[:0], nil, crypt, 1, nonce)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hi from a"), plain)

	// B encrypt for A
	crypt, err = hB.ConnectionState.eKey.EncryptDanger(crypt[:0], nil, []byte("hi from b"), 1, nonce)
	assert.NoError(t, err)
	assert.NotEqual(t, []byte("hi from b"), crypt)

	// A decrypt from B
	plain, err = hA.ConnectionState.dKey.DecryptDanger(plain[:0], []byte{}, crypt, 1, nonce)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hi from b"), plain)
}

func assertHostMapSize(t *testing.T, hm *HostMap, l int) {
	assert.Len(t, hm.Hosts, l, "Hosts was not the correct size")
	assert.Len(t, hm.RemoteIndexes, l, "RemoteIndexes was not the correct size")
	assert.Len(t, hm.Indexes, l, "Indexes was not the correct size")
}

func assertHostMapEntries(t *testing.T, hm *HostMap, entries ...*HostInfo) {
	assertHostMapSize(t, hm, len(entries))

	for _, v := range entries {
		assert.Equal(t, v, hm.Indexes[v.localIndexId])
		assert.Equal(t, v, hm.Hosts[v.hostId])
		assert.Equal(t, v, hm.RemoteIndexes[v.remoteIndexId])
	}
}

func assertHostMapPair(t *testing.T, hmA, hmB *HostMap, vpnIpA, vpnIpB uint32, addrA, addrB *udpAddr) (hAinB, hBinA *HostInfo) {
	var ok bool

	// Get both host infos
	hBinA, ok = hmA.Hosts[vpnIpB]
	assert.True(t, ok, "Host was not found by vpnIP in hmA")

	hAinB, ok = hmB.Hosts[vpnIpA]
	assert.True(t, ok, "Host was not found by vpnIP in hmB")

	// Check that both vpn and real addr are correct
	assert.Equal(t, vpnIpB, hBinA.hostId, "HostA vpnIp is wrong in hmB")
	assert.Equal(t, vpnIpA, hAinB.hostId, "HostB vpnIp is wrong in hmA")

	assert.Equal(t, addrB, hBinA.remote, "HostA remote is wrong in hmB")
	assert.Equal(t, addrA, hAinB.remote, "HostB remote is wrong in hmA")

	// Check that our indexes match
	assert.Equal(t, hBinA.localIndexId, hAinB.remoteIndexId, "Host B local index does not match host A remote index")
	assert.Equal(t, hBinA.remoteIndexId, hAinB.localIndexId, "Host B remote index does not match host A local index")

	checkIndexes := func(name string, hm *HostMap, hi *HostInfo) {
		hBbyIndex := hmA.Indexes[hBinA.localIndexId]
		assert.NotNil(t, hBbyIndex, "Could not host info by local index in %s", name)
		assert.Equal(t, &hBbyIndex, &hBinA, "%s Indexes map did not point to the right host info", name)

		//TODO: remote indexes are susceptible to collision
		hBbyRemoteIndex := hmA.RemoteIndexes[hBinA.remoteIndexId]
		assert.NotNil(t, hBbyIndex, "Could not host info by remote index in %s", name)
		assert.Equal(t, &hBbyRemoteIndex, &hBinA, "%s RemoteIndexes did not point to the right host info", name)
	}

	// Check hostmap indexes too
	checkIndexes("hmA", hmA, hBinA)
	checkIndexes("hmB", hmB, hAinB)

	return hAinB, hBinA
}

func newTestWriter(b *[]byte, err error) writer {
	return func(buf []byte, to *udpAddr) error {
		*b = (*b)[:len(buf)]
		copy(*b, buf)
		return err
	}
}

func newTestInterface(t assert.TestingT, c *cert.NebulaCertificate, privKey []byte) *Interface {
	cb, err := c.Marshal()
	assert.NoError(t, err)

	pub := c.Details.PublicKey
	c.Details.PublicKey = nil
	cbNoKey, err := c.Marshal()
	assert.NoError(t, err)
	c.Details.PublicKey = pub

	f := &Interface{}
	f.certState = &CertState{
		rawCertificate:      cb,
		privateKey:          privKey,
		publicKey:           pub,
		certificate:         c,
		rawCertificateNoKey: cbNoKey,
	}

	lh := NewLightHouse(
		false,
		ip2int(c.Details.Ips[0].IP),
		[]uint32{},
		10,
		1234,
		nil,
		true,
		time.Second,
		false,
	)

	f.lightHouse = lh
	f.hostMap = NewHostMap("main", c.Details.Ips[0], nil)
	f.metricHandshakes = metrics.GetOrRegisterHistogram("handshakes", nil, metrics.NewExpDecaySample(1028, 0.015))

	handshakeConfig := HandshakeConfig{
		tryInterval:    DefaultHandshakeTryInterval,
		retries:        DefaultHandshakeRetries,
		waitRotation:   DefaultHandshakeWaitRotation,
		triggerBuffer:  DefaultHandshakeTriggerBuffer,
		messageMetrics: newMessageMetricsOnlyRecvError(),
	}

	f.handshakeManager = NewHandshakeManager(c.Details.Ips[0], nil, f.hostMap, lh, nil, handshakeConfig)
	f.connectionManager = newConnectionManager(f, 1000, 1000)
	return f
}

func newTestCaCert(before, after time.Time, ips, subnets []*net.IPNet, groups []string) (*cert.NebulaCertificate, []byte, []byte, []byte) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}
	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           "test ca",
			NotBefore:      time.Unix(before.Unix(), 0),
			NotAfter:       time.Unix(after.Unix(), 0),
			PublicKey:      pub,
			IsCA:           true,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	if len(ips) > 0 {
		nc.Details.Ips = ips
	}

	if len(subnets) > 0 {
		nc.Details.Subnets = subnets
	}

	if len(groups) > 0 {
		nc.Details.Groups = groups
	}

	err = nc.Sign(priv)
	if err != nil {
		panic(err)
	}

	pem, err := nc.MarshalToPEM()
	if err != nil {
		panic(err)
	}

	return nc, pub, priv, pem
}

func newTestCert(ca *cert.NebulaCertificate, key []byte, name string, before, after time.Time, ip *net.IPNet, subnets []*net.IPNet, groups []string) (*cert.NebulaCertificate, []byte, []byte) {
	issuer, err := ca.Sha256Sum()
	if err != nil {
		panic(err)
	}

	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}
	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	if len(groups) == 0 {
		groups = []string{"test-group1", "test-group2", "test-group3"}
	}

	pub, rawPriv := x25519Keypair()

	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           name,
			Ips:            []*net.IPNet{ip},
			Subnets:        subnets,
			Groups:         groups,
			NotBefore:      time.Unix(before.Unix(), 0),
			NotAfter:       time.Unix(after.Unix(), 0),
			PublicKey:      pub,
			IsCA:           false,
			Issuer:         issuer,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	err = nc.Sign(key)
	if err != nil {
		panic(err)
	}

	return nc, pub, rawPriv
}

func x25519Keypair() ([]byte, []byte) {
	var pubkey, privkey [32]byte
	if _, err := io.ReadFull(rand.Reader, privkey[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return pubkey[:], privkey[:]
}
