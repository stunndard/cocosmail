package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogFileRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cocosmail.log")
	require.NoError(t, os.WriteFile(path, []byte("before\n"), 0600))
	maxSize, keep := int64(20), 2
	l, err := openLogFile(path, func() (int64, int) { return maxSize, keep })
	require.NoError(t, err)
	read := func(p string) string {
		b, _ := os.ReadFile(p)
		return string(b)
	}

	// the existing file counts
	l.Write([]byte("line 1\n"))
	l.Write([]byte("line 2\n"))
	assert.Equal(t, "before\nline 1\n", read(path+".1"))
	assert.Equal(t, "line 2\n", read(path))

	// a message is never split, even longer than the limit
	l.Write([]byte(strings.Repeat("x", 30) + "\n"))
	l.Write([]byte("line 3\n"))
	assert.Equal(t, "line 3\n", read(path))
	assert.Equal(t, strings.Repeat("x", 30)+"\n", read(path+".1"))
	assert.Equal(t, "line 2\n", read(path+".2"), "the oldest one deleted")

	// only keep files are kept
	l.Write([]byte(strings.Repeat("y", 20)))
	assert.Equal(t, "line 3\n", read(path+".1"))
	assert.NoFileExists(t, path+".3")

	// no rotation
	maxSize = 0
	l.Write([]byte(strings.Repeat("z", 100)))
	assert.Equal(t, strings.Repeat("y", 20)+strings.Repeat("z", 100), read(path))

	// moved away by someone else: a new file, nothing renamed
	maxSize = 20
	require.NoError(t, os.Rename(path, path+".moved"))
	l.Write([]byte("line 4\n"))
	assert.Equal(t, "line 4\n", read(path))
	assert.Equal(t, "line 3\n", read(path+".1"))

	// reopened after logrotate
	require.NoError(t, os.Rename(path, path+".old"))
	require.NoError(t, l.Reopen())
	l.Write([]byte("line 5\n"))
	assert.Equal(t, "line 5\n", read(path))
	assert.Equal(t, "line 4\n", read(path+".old"))
}
