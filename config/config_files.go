package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ReadConfigFiles will find all yaml files within path and read them in lexical order
func ReadConfigFiles(path string) ([]string, error) {
	files, err := resolve(path, true)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no config files found at %s", path)
	}

	sort.Strings(files)

	readFiles := []string{}
	for _, file := range files {
		f, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}

		readFiles = append(readFiles, string(f))
	}

	return readFiles, nil
}

// direct signifies if this is the config path directly specified by the user,
// versus a file/dir found by recursing into that path
func resolve(path string, direct bool) ([]string, error) {
	files := []string{}

	i, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !i.IsDir() {
		f, shouldAdd := checkFile(path, direct)
		if !shouldAdd {
			// If the file is not suitable we return
			// the original slice
			return files, err
		}

		return append(files, f), nil
	}

	paths, err := readDirNames(path)
	if err != nil {
		return nil, fmt.Errorf("problem while reading directory %s: %s", path, err)
	}

	for _, p := range paths {
		f, err := resolve(filepath.Join(path, p), false)
		if err != nil {
			return nil, err
		}

		files = append(files, f...)
	}

	return files, nil
}

func readDirNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	paths, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}

	sort.Strings(paths)
	return paths, nil
}

// checkFile returns the name of the file and wether we should
// add the file to the list of configs.
func checkFile(path string, direct bool) (string, bool) {
	ext := filepath.Ext(path)

	if !direct && ext != ".yaml" && ext != ".yml" {
		return "", false
	}

	ap, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}

	return ap, true
}
