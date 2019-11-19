package nebula

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"github.com/golang/protobuf/proto"
)

const (
	handshakeIXPSK0 = 0
	handshakeXXPSK0 = 1
)

func HandleIncomingHandshake(f *Interface, addr *udpAddr, packet []byte, h *Header, hostinfo *HostInfo) {
	newHostinfo, _ := f.handshakeManager.QueryIndex(h.RemoteIndex)
	//TODO: For stage 1 we won't have hostinfo yet but stage 2 and above would require it, this check may be helpful in those cases
	//if err != nil {
	//	l.WithError(err).WithField("udpAddr", addr).Error("Error while finding host info for handshake message")
	//	return
	//}

	tearDown := false
	switch h.Subtype {
	case handshakeIXPSK0:
		switch h.MessageCounter {
		case 1:
			tearDown = ixHandshakeStage1(f, addr, newHostinfo, packet, h)
		case 2:
			tearDown = ixHandshakeStage2(f, addr, newHostinfo, packet, h)
		}
	}

	if tearDown && newHostinfo != nil {
		f.handshakeManager.DeleteIndex(newHostinfo.localIndexId)
		f.handshakeManager.DeleteVpnIP(newHostinfo.hostId)
	}
}

func HandshakeBytesWithMAC(details *NebulaHandshakeDetails, key []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)

	b, err := proto.Marshal(details)
	if err != nil {
		return nil, errors.New("Unable to marshal nebula handshake")
	}
	mac.Write(b)
	sum := mac.Sum(nil)

	hs := &NebulaHandshake{
		Details: details,
		Hmac:    sum,
	}

	hsBytes, err := proto.Marshal(hs)
	if err != nil {
		l.Debugln("failed to generate NebulaHandshake protobuf", err)
	}

	return hsBytes, nil
}

func (hs *NebulaHandshake) CheckHandshakeMAC(keys [][]byte) bool {

	b, err := proto.Marshal(hs.Details)
	if err != nil {
		return false
	}

	for _, k := range keys {
		mac := hmac.New(sha256.New, k)
		mac.Write(b)
		expectedMAC := mac.Sum(nil)
		if hmac.Equal(hs.Hmac, expectedMAC) {
			return true
		}
	}

	//l.Debugln(hs.Hmac, expectedMAC)

	return false
}
