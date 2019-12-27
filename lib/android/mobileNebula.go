package mobileNebula

import (
	"fmt"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
)

func Main(configData string, tunFd int) string {
	err := nebula.Main(configData, false, "", &tunFd)
	return fmt.Sprintf("%s", err)
}

func GetConfigSetting(configData string, setting string) string {
	config := nebula.NewConfig()
	config.LoadString(configData)
	return config.GetString(setting, "")
}

func GetHostCertIP(configData string) (string) {
	c := GetConfigSetting(configData, "pki.cert")
	rawCert := []byte(c)
	crt, _, err := cert.UnmarshalNebulaCertificateFromPEM(rawCert)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	return crt.Details.Ips[0].IP.String()
	//return "HI"
}

func GetHostCertMask(configData string) (int) {
	c := GetConfigSetting(configData, "pki.cert")
	rawCert := []byte(c)
	crt, _, err := cert.UnmarshalNebulaCertificateFromPEM(rawCert)
	if err != nil {
		fmt.Println(err)
		return 0 
	}

  _, pre := crt.Details.Ips[0].Mask.Size()

	return pre
	//return "HI"
}
