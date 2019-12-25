package mobileNebula

import (
	"fmt"
	"github.com/slackhq/nebula"
)

func Main(configData string, tunFd int) string {
	err := nebula.Main(configData, false, "", &tunFd)
  return fmt.Sprintf("%s", err)
}
