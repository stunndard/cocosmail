package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteDefaultFiles(t *testing.T) {
	base := t.TempDir()
	written, err := WriteDefaultFiles(base)
	require.NoError(t, err)
	for _, want := range []string{"conf/", "conf/cocosmail.cfg.base", "plugins/config.go", "plugins/fail2ban/fail2ban.go", "tpl/bounce.tpl", "ssl/", "ssl/README.txt"} {
		assert.Contains(t, written, want)
	}
	// no shared test keys, no config that would be imported
	for _, notWanted := range []string{"ssl/server.key", "conf/cocosmail.cfg"} {
		_, err := os.Stat(filepath.Join(base, notWanted))
		assert.True(t, os.IsNotExist(err), notWanted)
	}
	fi, err := os.Stat(filepath.Join(base, "conf/cocosmail.cfg.base"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
	fi, err = os.Stat(filepath.Join(base, "ssl"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), fi.Mode().Perm())

	// existing files are kept, missing ones written again
	tpl := filepath.Join(base, "tpl/bounce.tpl")
	require.NoError(t, os.WriteFile(tpl, []byte("my template"), 0644))
	require.NoError(t, os.Remove(filepath.Join(base, "plugins/config.go")))
	written, err = WriteDefaultFiles(base)
	require.NoError(t, err)
	assert.Equal(t, []string{"plugins/config.go"}, written)
	data, _ := os.ReadFile(tpl)
	assert.Equal(t, "my template", string(data))
}
