package core

import (
	"net"
	"strconv"
	"testing"

	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplySettings(t *testing.T) {
	Logger = logrus.New()
	var err error
	DB, err = gorm.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer DB.Close()

	base := map[string]string{
		"me":           "mail.example.com",
		"smtpd_launch": "true",
		"smtpd_dsns":   "[::1]:0:mail.example.com:nossl:cert",
		"pop3d_launch": "true",
		"pop3d_dsns":   "[::1]:0:mail.example.com:nossl:cert",
	}
	_, err = ImportSettings(DB, base, false)
	require.NoError(t, err)
	v := SettingsVersion(DB)
	assert.Greater(t, v, int64(0))
	Cfg = &Config{}
	values, inDB, err := CurrentSettings(DB)
	require.NoError(t, err)
	assert.True(t, inDB)
	require.NoError(t, Cfg.Load(values))

	// nothing changed
	assert.Equal(t, "", applySettings())

	// live setting: applied at once
	require.NoError(t, SettingsToDB(DB, map[string]string{"smtpd_max_hops": "42"}))
	assert.Equal(t, v+1, SettingsVersion(DB))
	assert.Equal(t, "", applySettings())
	assert.Equal(t, 42, Cfg.GetSmtpdMaxHops())

	// setting needing restart: restart requested, running config unchanged
	require.NoError(t, SettingsToDB(DB, map[string]string{"smtpd_dsns": "[::1]:0:other.example.com:nossl:cert"}))
	assert.Contains(t, applySettings(), "COCOSMAIL_SMTPD_DSNS")
	assert.Equal(t, "[::1]:0:mail.example.com:nossl:cert", Cfg.GetSmtpdDsns())
	require.NoError(t, SettingsToDB(DB, map[string]string{"smtpd_dsns": base["smtpd_dsns"]}))

	// preflight fails: POP3 in clear text on a public address, rolled back
	require.NoError(t, SettingsToDB(DB, map[string]string{"pop3d_dsns": "192.0.2.1:110:mail.example.com:nossl:cert"}))
	assert.Equal(t, "", applySettings())
	stored, _ := SettingsFromDB(DB)
	assert.Equal(t, base["pop3d_dsns"], stored["pop3d_dsns"])

	// preflight fails: certificate missing for an ssl listener
	require.NoError(t, SettingsToDB(DB, map[string]string{"pop3d_dsns": "[::1]:0:mail.example.com:ssl:nosuchcert"}))
	assert.Equal(t, "", applySettings())
	stored, _ = SettingsFromDB(DB)
	assert.Equal(t, base["pop3d_dsns"], stored["pop3d_dsns"])

	// preflight fails: port in use by another program
	l, err := net.Listen("tcp", "[::1]:0")
	require.NoError(t, err)
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, SettingsToDB(DB, map[string]string{"smtpd_dsns": "[::1]:" + strconv.Itoa(port) + ":mail.example.com:nossl:cert"}))
	assert.Equal(t, "", applySettings())
	stored, _ = SettingsFromDB(DB)
	assert.Equal(t, base["smtpd_dsns"], stored["smtpd_dsns"])

	// invalid value written directly in DB: rolled back, config unchanged
	require.NoError(t, DB.Save(&DbSetting{Key: "smtpd_max_hops", Value: "many"}).Error)
	require.NoError(t, SettingsToDB(DB, map[string]string{}))
	assert.Equal(t, "", applySettings())
	stored, _ = SettingsFromDB(DB)
	assert.Equal(t, "42", stored["smtpd_max_hops"])
	assert.Equal(t, 42, Cfg.GetSmtpdMaxHops())
}
