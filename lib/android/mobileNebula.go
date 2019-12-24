package mobileNebula

import (
	"github.com/slackhq/nebula"
)

func Main(configData string, tunFd int) {
	nebula.Main(configData, false, "", &tunFd)
}
