package core

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/stunndard/cocosmail/dist"
)

// WriteDefaultFiles writes the default files embedded in the binary (config
// example, plugins, templates, ssl/README.txt) into base, if they don't exist.
// Existing files are never changed. It returns the paths written.
func WriteDefaultFiles(base string) (written []string, err error) {
	err = fs.WalkDir(dist.Files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		target := filepath.Join(base, filepath.FromSlash(name))
		// config and keys: owner only
		private := strings.HasPrefix(name, "conf") || strings.HasPrefix(name, "ssl")
		if d.IsDir() {
			mode := os.FileMode(0755)
			if private {
				mode = 0700
			}
			if _, err := os.Stat(target); err == nil {
				return nil
			}
			if err := os.MkdirAll(target, mode); err != nil {
				return err
			}
			written = append(written, name+"/")
			return nil
		}
		if _, err := os.Stat(target); err == nil {
			return nil
		}
		data, err := dist.Files.ReadFile(name)
		if err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if private {
			mode = 0600
		}
		if err := os.WriteFile(target, data, mode); err != nil {
			return err
		}
		written = append(written, name)
		return nil
	})
	if err != nil {
		return written, err
	}
	// empty directories
	for _, dir := range []string{LogDir} {
		target := filepath.Join(base, dir)
		if _, err := os.Stat(target); err == nil {
			continue
		}
		if err := os.MkdirAll(target, 0700); err != nil {
			return written, err
		}
		written = append(written, dir+"/")
	}
	return written, nil
}
