package mobileNebula

import (
	"fmt"
	"net"
	"runtime"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
)

var exiter bool = false
var rebind chan struct{}

type ConfigStuff struct {
	IP       string
	Mask     int
	Network  string
	MaskCIDR string
	RawCert  string
}

func Main(configData string, tunFd int) string {
	rebind = make(chan struct{})
	if runtime.GOOS == "android" {
		err := nebula.Main(configData, false, "", &tunFd, rebind)
		return fmt.Sprintf("%s", err)
	} else if runtime.GOOS == "darwin" && (runtime.GOARCH == "arm" || runtime.GOARCH == "arm64") {
		go nebula.Main(configData, false, "", &tunFd, rebind)
	}
	return fmt.Sprintf("%s", "started")
}

func Rebind() {
	rebind <- struct{}{}
}

func GetConfigSetting(configData string, setting string) string {
	config := nebula.NewConfig()
	config.LoadString(configData)
	return config.GetString(setting, "")
}

func ParseConfig(configData string) *ConfigStuff {
	config := nebula.NewConfig()
	config.LoadString(configData)

	c := GetConfigSetting(configData, "pki.cert")
	rawCert := []byte(c)
	crt, _, err := cert.UnmarshalNebulaCertificateFromPEM(rawCert)
	if err != nil {
		return nil
	}
	addr, ipNet, err := net.ParseCIDR(crt.Details.Ips[0].String())
	if err != nil {
		return &ConfigStuff{}
	}
	mask, _ := ipNet.Mask.Size()

	if len(ipNet.Mask) != 4 {
		panic("ipv4Mask: len must be 4 bytes")
	}

	mcidr := fmt.Sprintf("%d.%d.%d.%d", ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3])

	cs := &ConfigStuff{
		IP:       addr.String(),
		Mask:     mask,
		Network:  ipNet.IP.String(),
		MaskCIDR: mcidr,
		RawCert:  c,
	}
	return cs
}

func Exit() {
	exiter = true
}
