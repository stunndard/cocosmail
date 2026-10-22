package core

import (
	"os"
	"strconv"
	"sync"
)

// logFile is the log file, rotated by size: when it would grow over the
// limit, NAME becomes NAME.1, NAME.1 becomes NAME.2... and the oldest files
// are deleted. The limits are read at every write, so a change of
// log_max_size or log_max_files applies at once.
type logFile struct {
	mu   sync.Mutex
	path string
	// limits returns the maximum size in bytes (0: no rotation) and the
	// number of rotated files kept
	limits func() (maxSize int64, keep int)
	f      *os.File
	size   int64
}

func openLogFile(path string, limits func() (int64, int)) (*logFile, error) {
	l := &logFile{path: path, limits: limits}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *logFile) open() error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, fi.Size()
	return nil
}

// Write writes p, after a rotation if the file would grow over the limit.
// A message is never split between two files.
func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if maxSize, keep := l.limits(); maxSize > 0 && l.size > 0 && l.size+int64(len(p)) > maxSize {
		// can't rotate: keep logging in the same file
		_ = l.rotate(keep)
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

// rotate renames the log files and opens a new one. If another process
// (cocosmail command line, logrotate) already moved the file, the new
// file is only opened.
func (l *logFile) rotate(keep int) error {
	fi, err := os.Stat(l.path)
	if err != nil {
		return l.reopen()
	}
	if cur, err := l.f.Stat(); err != nil || !os.SameFile(fi, cur) {
		return l.reopen()
	}
	if keep <= 0 {
		os.Remove(l.path)
	} else {
		os.Remove(l.rotated(keep))
		for i := keep - 1; i > 0; i-- {
			os.Rename(l.rotated(i), l.rotated(i+1))
		}
		if err := os.Rename(l.path, l.rotated(1)); err != nil {
			return err
		}
	}
	return l.reopen()
}

func (l *logFile) rotated(i int) string {
	return l.path + "." + strconv.Itoa(i)
}

// reopen closes the file and opens path again
func (l *logFile) reopen() error {
	old := l.f
	if err := l.open(); err != nil {
		return err
	}
	old.Close()
	return nil
}

// Reopen opens the log file again, after it was moved away (by logrotate)
func (l *logFile) Reopen() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reopen()
}

// logOut is the log file in use, nil when logging to stdout or nowhere
var logOut *logFile

// ReopenLog opens the log file again, on SIGHUP
func ReopenLog() {
	if logOut == nil {
		return
	}
	if err := logOut.Reopen(); err != nil {
		Logger.Error("log file not reopened: " + err.Error())
	}
}
