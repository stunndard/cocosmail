package core

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

// spoolDir is where messages are received, in the disk store
const spoolDir = "tmp"

// headersSuffix names the file of headers added on top of a message at
// delivery, beside it in the store: <key>.headers. The results of checks
// done once the message is received are there, as the top of the message
// file is written before.
const headersSuffix = ".headers"

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
	// bytes written, and where the data of the client starts, after our
	// headers
	size, dataStart int64
	// headers added on top at delivery
	headers string
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
	n, err := sp.w.Write(p)
	sp.size += int64(n)
	return n, err
}

// WriteString appends s to the message
func (sp *Spool) WriteString(s string) (int, error) {
	n, err := sp.w.WriteString(s)
	sp.size += int64(n)
	return n, err
}

// markDataStart tells that the data of the client starts here
func (sp *Spool) markDataStart() {
	sp.dataStart = sp.size
}

// setHeaders sets the headers added on top of the message at delivery
func (sp *Spool) setHeaders(h string) {
	sp.headers = h
}

// Reader returns the message written so far, with the headers added on top
// at delivery
func (sp *Spool) Reader() (io.ReadCloser, error) {
	f, err := sp.readerAt(0)
	if err != nil || sp.headers == "" {
		return f, err
	}
	return messageReader{io.MultiReader(strings.NewReader(sp.headers), f), f}, nil
}

// clientData returns the message as the client sent it, without our headers
func (sp *Spool) clientData() (io.ReadCloser, error) {
	return sp.readerAt(sp.dataStart)
}

func (sp *Spool) readerAt(offset int64) (*os.File, error) {
	if err := sp.w.Flush(); err != nil {
		return nil, err
	}
	f, err := os.Open(sp.path)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
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
	// the headers first: the message is delivered once it's there
	if sp.headers != "" {
		if err := writeSynced(sp.path+headersSuffix, sp.headers); err != nil {
			return err
		}
		if err := os.Rename(sp.path+headersSuffix, dst+headersSuffix); err != nil {
			return err
		}
	}
	if err := os.Rename(sp.path, dst); err != nil {
		return err
	}
	sp.done = true
	return nil
}

// writeSynced writes data to a new file p, on disk when it returns
func writeSynced(p, data string) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(data); err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		os.Remove(p)
	}
	return err
}

// Abort removes the message, unless it was queued
func (sp *Spool) Abort() {
	if sp.done {
		return
	}
	sp.done = true
	_ = sp.f.Close()
	_ = os.Remove(sp.path)
	if sp.headers != "" {
		_ = os.Remove(sp.path + headersSuffix)
		_ = os.Remove(sp.store.getStoragePath(sp.key) + headersSuffix)
	}
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
