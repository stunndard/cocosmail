package core

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKey = "6a926acd9548b12700f0fa3913230f5b2d59d6d4"

func TestStoragePath(t *testing.T) {
	s := &diskStore{"/store"}
	assert.Equal(t, "/store/6/a/"+testKey, s.getStoragePath(testKey))
	assert.Equal(t, "/store/6/a/"+testKey+".headers", s.getStoragePath(testKey+".headers"))
	assert.Equal(t, "/store/a", s.getStoragePath("a"))
	assert.Equal(t, "/store/a/ab", s.getStoragePath("ab"))
}

func TestDiskStoreLevels(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	require.NoError(t, err)
	require.NoError(t, s.Put(testKey, strings.NewReader("message")))
	_, err = os.Stat(filepath.Join(dir, "6", "a", testKey))
	require.NoError(t, err)
	r, err := s.Get(testKey)
	require.NoError(t, err)
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	r.Close()
	assert.Equal(t, "message", string(b))
	require.NoError(t, s.Del(testKey))
	_, err = s.Get(testKey)
	assert.Error(t, err)
}
