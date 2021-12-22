package config

import (
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"testing"
)

// Given a path check if the file is correctly read.
func TestReadConfigFilesSimpleFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "config_files_simple_file_test")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	f, err := ioutil.TempFile(dir, "test_nebula_config_simple_file_*")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = f.Close()
	}()

	expected := "Expected string to be read"

	if _, err := io.WriteString(f, expected); err != nil {
		t.Fatal(err)
		return
	}

	read, err := ReadConfigFiles(f.Name())
	if err != nil {
		t.Fatal(err)
		return
	}

	if len(read) != 1 {
		t.Fatalf("len(read)=%v, want %v", len(read), 1)
		return
	}

	if read[0] != expected {
		t.Fatalf("read[0]=%v, want %v", read[0], expected)
		return
	}
}

// Check if .yaml/.yml files in folder get picked up correctly, even when mixed with random files.
func TestReadConfigFilesMultipleFilesInFolder(t *testing.T) {
	dir, err := ioutil.TempDir("", "config_files_multiple_files_test")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	f1, err := ioutil.TempFile(dir, "config_files_multiple_files_test_*.yaml")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = f1.Close()
	}()

	f2, err := ioutil.TempFile(dir, "config_files_multiple_files_test_*.notyaml")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = f2.Close()
	}()

	f3, err := ioutil.TempFile(dir, "config_files_multiple_files_test_*.yaml")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = f3.Close()
	}()

	expected := "Expected string to be read"
	notyaml := "Not YAML"

	if _, err := io.WriteString(f1, expected); err != nil {
		t.Fatal(err)
		return
	}

	if _, err := io.WriteString(f2, notyaml); err != nil {
		t.Fatal(err)
		return
	}

	if _, err := io.WriteString(f3, expected); err != nil {
		t.Fatal(err)
		return
	}

	read, err := ReadConfigFiles(dir)
	if err != nil {
		t.Fatal(err)
		return
	}

	if len(read) != 2 {
		t.Fatalf("len(read)=%v, want %v", len(read), 2)
		return
	}

	// Check every file read contains the expected string
	for i, v := range read {
		if v != expected {
			t.Fatalf("read[%v]=%v, want %v", i, v, expected)
			return
		}
	}
}

// Check if files are read in sorted in a lexicographical fashion
func TestReadConfigFilesMultipleFilesInFolderCheckLexicographicalSorting(t *testing.T) {
	// These are starting to get really long, lol
	dir, err := ioutil.TempDir("", "config_files_multiple_files_check_lexicographical_sorting_test")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	f1, err := ioutil.TempFile(dir, "a*.yaml")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = f1.Close()
	}()

	f2, err := ioutil.TempFile(dir, "b*.yaml")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = f2.Close()
	}()

	f3, err := ioutil.TempFile(dir, "c*.yaml")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = f3.Close()
	}()

	if _, err := io.WriteString(f1, "0"); err != nil {
		t.Fatal(err)
		return
	}

	if _, err := io.WriteString(f2, "1"); err != nil {
		t.Fatal(err)
		return
	}

	if _, err := io.WriteString(f3, "2"); err != nil {
		t.Fatal(err)
		return
	}

	read, err := ReadConfigFiles(dir)
	if err != nil {
		t.Fatal(err)
		return
	}

	if len(read) != 3 {
		t.Fatalf("len(read)=%v, want %v", len(read), 3)
		return
	}

	// Check if the slice sorting follows the assumptions we made before
	for i, v := range read {
		if v != strconv.Itoa(i) {
			t.Fatalf("read[%v]=%v, want %v", i, v, strconv.Itoa(i))
			return
		}
	}
}

func TestReadConfigFilesMultipleFilesInMultipleFoldersSorting(t *testing.T) {
	rootdir, err := ioutil.TempDir("", "config_files_multiple_files_multiple_folders_sorting_test")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = os.RemoveAll(rootdir)
	}()

	dir1, err := ioutil.TempDir(rootdir, "dir1")
	if err != nil {
		t.Fatal(err)
		return
	}

	dir2, err := ioutil.TempDir(rootdir, "dir2")
	if err != nil {
		t.Fatal(err)
		return
	}

	f1, err := ioutil.TempFile(dir1, "a*.yaml")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = f1.Close()
	}()

	f2, err := ioutil.TempFile(dir1, "b*.yaml")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = f2.Close()
	}()

	f3, err := ioutil.TempFile(dir2, "a*.yaml")
	defer func() {
		_ = f3.Close()
	}()
	if err != nil {
		t.Fatal(err)
		return
	}

	f4, err := ioutil.TempFile(dir2, "b*.yaml")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer func() {
		_ = f4.Close()
	}()

	// The first file is f1, since dir1_XXXXXX/aXXXXX.yaml is
	// lexicographically sorted first
	if _, err := io.WriteString(f1, "0"); err != nil {
		t.Fatal(err)
		return
	}

	// The second file is f2, since dir1_XXXXXX/bXXXXX.yaml is
	// lexicographically sorted as second
	if _, err := io.WriteString(f2, "1"); err != nil {
		t.Fatal(err)
		return
	}

	if _, err := io.WriteString(f3, "2"); err != nil {
		t.Fatal(err)
		return
	}

	if _, err := io.WriteString(f4, "3"); err != nil {
		t.Fatal(err)
		return
	}

	read, err := ReadConfigFiles(rootdir)
	if err != nil {
		t.Fatal(err)
		return
	}

	if len(read) != 4 {
		t.Fatalf("len(read)=%v, want %v", len(read), 3)
		return
	}

	// Check if the slice sorting follows the assumptions we made before
	for i, v := range read {
		if v != strconv.Itoa(i) {
			t.Fatalf("read[%v]=%v, want %v", i, v, strconv.Itoa(i))
			return
		}
	}
}
