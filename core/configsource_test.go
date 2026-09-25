package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyConfigSource(t *testing.T) {
	Logger = logrus.New()
	db, err := gorm.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()
	defer func() { ConfigFilePath = "" }()
	require.NoError(t, InitDB(db))

	path := filepath.Join(t.TempDir(), "cocosmail.cfg")
	require.NoError(t, os.WriteFile(path, []byte(
		"COCOSMAIL_ME=file.example.com\n"+
			"COCOSMAIL_SMTPD_DSNS=[::1]:25:file.example.com:nossl:cert\n"+
			"COCOSMAIL_POP3D_DSNS=[::1]:995:file.example.com:ssl:cert\n"+
			"COCOSMAIL_SMTPD_MAX_HOPS=33\n"+
			"COCOSMAIL_DB_SOURCE=other.db\n"), 0600))

	// file mode: file is imported, environment overrides it
	ConfigFilePath = path
	t.Setenv("COCOSMAIL_SMTPD_MAX_HOPS", "44")
	require.NoError(t, applyConfigSource(db))
	values, _ := SettingsFromDB(db)
	assert.Equal(t, "file.example.com", values["me"])
	assert.Equal(t, "44", values["smtpd_max_hops"])
	assert.Equal(t, "300", values["smtpd_server_timeout"])
	_, hasBootstrap := values["db_source"]
	assert.False(t, hasBootstrap)
	abs, _ := filepath.Abs(path)
	assert.Equal(t, abs, SettingsManagedBy(db))

	// sources: file, env, db
	_, sources, err := EffectiveSettings(db)
	require.NoError(t, err)
	assert.Equal(t, SourceDB, sources["me"])
	assert.Equal(t, SourceFile, sources["db_source"])

	// file changed: it wins at next start, missing settings get their default
	require.NoError(t, SettingsToDB(db, map[string]string{"smtpd_max_vrfy": "5"}))
	require.NoError(t, os.WriteFile(path, []byte(
		"COCOSMAIL_ME=changed.example.com\n"+
			"COCOSMAIL_SMTPD_DSNS=[::1]:25:file.example.com:nossl:cert\n"+
			"COCOSMAIL_POP3D_DSNS=[::1]:995:file.example.com:ssl:cert\n"), 0600))
	require.NoError(t, applyConfigSource(db))
	values, _ = SettingsFromDB(db)
	assert.Equal(t, "changed.example.com", values["me"])
	assert.Equal(t, "0", values["smtpd_max_vrfy"])

	// invalid file: server doesn't start, DB unchanged
	require.NoError(t, os.WriteFile(path, []byte("COCOSMAIL_ME=x\nCOCOSMAIL_SMTPD_MAX_VRFY=many\n"), 0600))
	assert.Error(t, applyConfigSource(db))
	values, _ = SettingsFromDB(db)
	assert.Equal(t, "changed.example.com", values["me"])

	// database mode: settings stay, file no longer manages them
	ConfigFilePath = ""
	require.NoError(t, applyConfigSource(db))
	assert.Equal(t, "", SettingsManagedBy(db))
	values, _ = SettingsFromDB(db)
	assert.Equal(t, "changed.example.com", values["me"])
}

func TestApplyConfigSourceData(t *testing.T) {
	Logger = logrus.New()
	db, err := gorm.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()
	defer func() { ConfigFilePath = "" }()
	require.NoError(t, InitDB(db))

	path := filepath.Join(t.TempDir(), "cocosmail.yaml")
	write := func(login string) {
		require.NoError(t, os.WriteFile(path, []byte(
			"settings:\n"+
				"  me: file.example.com\n"+
				"  smtpd_dsns: '[::1]:25:file.example.com:nossl:cert'\n"+
				"  pop3d_dsns: '[::1]:995:file.example.com:ssl:cert'\n"+
				"domains:\n"+
				"  - {name: example.com, local: true}\n"+
				"users:\n"+
				"  - {login: "+login+", password: secret1, mailbox: true}\n"), 0600))
	}
	logins := func() (l []string) {
		d, err := ExportData(db)
		require.NoError(t, err)
		for _, u := range d.Users {
			l = append(l, u.Login)
		}
		return
	}

	// file mode, empty database: settings and data imported
	write("john@example.com")
	ConfigFilePath = path
	require.NoError(t, applyConfigSource(db))
	values, _ := SettingsFromDB(db)
	assert.Equal(t, "file.example.com", values["me"])
	assert.Equal(t, []string{"john@example.com"}, logins())

	// next starts: settings again, data stays as changed in DB
	write("jane@example.com")
	require.NoError(t, applyConfigSource(db))
	assert.Equal(t, []string{"john@example.com"}, logins())

	// invalid data in an empty database: the server doesn't start
	_, err = ImportData(db, &Data{}, true, false)
	require.NoError(t, err)
	write("x@nowhere.example")
	assert.ErrorContains(t, applyConfigSource(db), "nowhere.example must be a local domain")
}
