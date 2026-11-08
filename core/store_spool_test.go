package core

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func spoolTestStore(t *testing.T) string {
	Logger = logrus.New()
	dir := t.TempDir()
	old := Cfg
	t.Cleanup(func() { Cfg = old })
	Cfg = &Config{}
	Cfg.cfg.StoreDriver = "disk"
	Cfg.cfg.StoreSource = dir
	return dir
}

func spoolFiles(t *testing.T, dir string) []string {
	entries, err := os.ReadDir(filepath.Join(dir, spoolDir))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestSpoolCommit(t *testing.T) {
	dir := spoolTestStore(t)
	sp, err := NewSpool()
	require.NoError(t, err)
	_, err = sp.WriteString("Subject: hi\r\n\r\n")
	require.NoError(t, err)
	_, err = sp.Write([]byte("body\r\n"))
	require.NoError(t, err)

	// what's written so far can be read, for clamav and plugins
	r, err := sp.Reader()
	require.NoError(t, err)
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	assert.Equal(t, "Subject: hi\r\n\r\nbody\r\n", string(b))

	require.NoError(t, sp.commit())
	sp.Abort() // no-op once queued
	assert.Empty(t, spoolFiles(t, dir))

	st, err := NewDiskStore(dir)
	require.NoError(t, err)
	got, err := st.Get(sp.key)
	require.NoError(t, err)
	b, err = io.ReadAll(got)
	require.NoError(t, err)
	assert.Equal(t, "Subject: hi\r\n\r\nbody\r\n", string(b))
}

func TestSpoolAbort(t *testing.T) {
	dir := spoolTestStore(t)
	sp, err := NewSpool()
	require.NoError(t, err)
	_, err = sp.WriteString("data")
	require.NoError(t, err)
	assert.Len(t, spoolFiles(t, dir), 1)
	sp.Abort()
	sp.Abort()
	assert.Empty(t, spoolFiles(t, dir))
	_, err = os.Stat(sp.store.getStoragePath(sp.key))
	assert.True(t, os.IsNotExist(err))
}

func TestCleanSpool(t *testing.T) {
	dir := spoolTestStore(t)
	old, err := NewSpool()
	require.NoError(t, err)
	recent, err := NewSpool()
	require.NoError(t, err)
	_ = old.f.Close()
	_ = recent.f.Close()
	past := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(old.path, past, past))

	CleanSpool(dir)
	assert.Equal(t, []string{recent.key}, spoolFiles(t, dir))
}
