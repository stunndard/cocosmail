package core

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	baseDir     string
	baseDirOnce sync.Once
)

// BaseDir returns the directory where the cocosmail binary is.
// All cocosmail files (db, store, mailboxes, ssl, tpl, plugins...) live there
// by default, so the whole directory can be copied to another server as is.
func BaseDir() string {
	baseDirOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			exe = os.Args[0]
		}
		// symlink in /usr/local/bin -> the real install directory
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		baseDir, _ = filepath.Abs(filepath.Dir(exe))
	})
	return baseDir
}

// AbsPath returns p if it's absolute, otherwise p relative to BaseDir
func AbsPath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(BaseDir(), p)
}

// sqliteAbsSource makes the file of a sqlite source ("file?params") relative to BaseDir
func sqliteAbsSource(src string) string {
	if src == "" || strings.HasPrefix(src, ":memory:") || strings.HasPrefix(src, "file:") {
		return src
	}
	file, params := src, ""
	if i := strings.Index(src, "?"); i != -1 {
		file, params = src[:i], src[i:]
	}
	return AbsPath(file) + params
}
