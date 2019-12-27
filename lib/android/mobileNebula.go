package mobileNebula

import (
	"fmt"
	"net"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
)

type ConfigStuff struct {
	IP      string
	Mask    int
	RawCert string
}

func Main(configData string, tunFd int) string {
	err := nebula.Main(configData, false, "", &tunFd)
	return fmt.Sprintf("%s", err)
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

	cs := &ConfigStuff{
		IP:      addr.String(),
		Mask:    mask,
		RawCert: c,
	}
	return cs
}
