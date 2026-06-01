package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultPath returns a path to a config file alongside the running executable, preferring config.yaml over config.yml.
// If neither file exists an error is returned that names both paths checked.
func DefaultPath() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", err
	}
	return defaultPathInDir(filepath.Dir(ex))
}

func defaultPathInDir(dir string) (string, error) {
	yamlPath := filepath.Join(dir, "config.yaml")
	if _, err := os.Stat(yamlPath); err == nil {
		return yamlPath, nil
	}
	ymlPath := filepath.Join(dir, "config.yml")
	if _, err := os.Stat(ymlPath); err == nil {
		return ymlPath, nil
	}
	return "", fmt.Errorf("no default config found at %s or %s", yamlPath, ymlPath)
}
