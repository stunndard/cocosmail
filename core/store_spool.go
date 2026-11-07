package core

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path"
	"time"
)

// spoolDir is where messages are received, in the disk store
const spoolDir = "tmp"

// Spool is a message being received, written to a file in the disk store
// (store/tmp) as it comes. It's queued by renaming the file to its place in
// the store, so a big message is never held in memory.
type Spool struct {
	store *diskStore
	key   string
	path  string
	f     *os.File
	w     *bufio.Writer
	done  bool
}

// NewSpool creates the file of a new message
func NewSpool() (*Spool, error) {
	st, err := NewStore(Cfg.GetStoreDriver(), Cfg.GetStoreSource())
	if err != nil {
		return nil, err
	}
	ds, ok := st.(*diskStore)
	if !ok {
		return nil, errors.New("store " + Cfg.GetStoreDriver() + " can't receive messages into files")
	}
	key, err := NewUUID()
	if err != nil {
		return nil, err
	}
	dir := path.Join(ds.basePath, spoolDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	p := path.Join(dir, key)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	return &Spool{store: ds, key: key, path: p, f: f, w: bufio.NewWriterSize(f, 64*1024)}, nil
}

// Write appends p to the message
func (sp *Spool) Write(p []byte) (int, error) {
	return sp.w.Write(p)
}

// WriteString appends s to the message
func (sp *Spool) WriteString(s string) (int, error) {
	return sp.w.WriteString(s)
}

// Reader returns the message written so far
func (sp *Spool) Reader() (io.ReadCloser, error) {
	if err := sp.w.Flush(); err != nil {
		return nil, err
	}
	return os.Open(sp.path)
}

// commit puts the message in the store, under its key. It's on disk when
// commit returns, before the client is told it's queued.
func (sp *Spool) commit() error {
	if err := sp.w.Flush(); err != nil {
		return err
	}
	if err := sp.f.Sync(); err != nil {
		return err
	}
	if err := sp.f.Close(); err != nil {
		return err
	}
	dst := sp.store.getStoragePath(sp.key)
	if err := os.MkdirAll(path.Dir(dst), 0766); err != nil {
		return err
	}
	if err := os.Rename(sp.path, dst); err != nil {
		return err
	}
	sp.done = true
	return nil
}

// Abort removes the message, unless it was queued
func (sp *Spool) Abort() {
	if sp.done {
		return
	}
	sp.done = true
	_ = sp.f.Close()
	_ = os.Remove(sp.path)
}

// CleanSpool removes the files of messages whose reception was cut by a crash.
// Not the newest ones: in cluster mode, other servers may share the store.
func CleanSpool(storeSource string) {
	dir := path.Join(diskStorePath(storeSource), spoolDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || time.Since(info.ModTime()) < time.Hour {
			continue
		}
		if err := os.Remove(path.Join(dir, e.Name())); err == nil {
			Logger.Info("removed unfinished message " + path.Join(dir, e.Name()))
		}
	}
}
