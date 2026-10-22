package core

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAbsPath(t *testing.T) {
	assert.True(t, filepath.IsAbs(BaseDir()))
	assert.Equal(t, "/var/mail", AbsPath("/var/mail"))
	assert.Equal(t, filepath.Join(BaseDir(), "mailboxes"), AbsPath("mailboxes"))
}

func TestSqliteAbsSource(t *testing.T) {
	assert.Equal(t, filepath.Join(BaseDir(), "db/cocosmail.db")+"?_busy_timeout=60000", sqliteAbsSource("db/cocosmail.db?_busy_timeout=60000"))
	assert.Equal(t, "/srv/cocosmail.db?x=1", sqliteAbsSource("/srv/cocosmail.db?x=1"))
	assert.Equal(t, ":memory:", sqliteAbsSource(":memory:"))
	assert.Equal(t, "file:test.db?cache=shared", sqliteAbsSource("file:test.db?cache=shared"))
}
