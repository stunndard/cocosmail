package core

import (
	"reflect"
	"testing"

	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSettingsMatchConfig(t *testing.T) {
	seen := make(map[string]bool)
	for _, s := range Settings {
		assert.False(t, seen[s.Key], "duplicate setting %s", s.Key)
		seen[s.Key] = true
		_, ok := configFields[s.Key]
		assert.True(t, ok, "setting %s has no config field", s.Key)
		assert.NotEmpty(t, s.Section, s.Key)
		assert.NotEmpty(t, s.Description, s.Key)
		if s.Required {
			assert.Empty(t, s.Default, "required setting %s has a default", s.Key)
		}
		if s.RequiredWith != "" {
			assert.Equal(t, reflect.Bool, SettingKind(s.RequiredWith), s.Key)
		}
		assert.NoError(t, ValidateSetting(s.Key, s.Default), "default of %s", s.Key)
	}
	typ := reflect.TypeOf(configValues{})
	for i := 0; i < typ.NumField(); i++ {
		key := typ.Field(i).Tag.Get("name")
		assert.True(t, seen[key], "config field %s has no setting", key)
	}
	for key, s := range settingsByKey {
		assert.Equal(t, s.Bootstrap, key == "db_driver" || key == "db_source", key)
	}
}

func TestValidateSetting(t *testing.T) {
	valid := map[string]string{
		"smtpd_max_hops":      "30",
		"smtpd_max_databytes": "50000000",
		"smtpd_spf_check":     "false",
		"smtpd_dsns":          "[::]:25:mail.example.com:nossl:example.com",
		"smtpd_spf_action":    "reject:reject:accept:reject:accept:accept",
		"deliverd_local_ips":  "192.0.2.1:mail.example.com|[2001:db8::1]:mail.example.com",
		"lda_type":            "dovecot",
		"rest_server_ip":      "::1",
		"me":                  "",
	}
	for k, v := range valid {
		assert.NoError(t, ValidateSetting(k, v), "%s=%s", k, v)
	}
	invalid := map[string]string{
		"no_such_setting":     "1",
		"smtpd_max_hops":      "many",
		"smtpd_max_databytes": "-1",
		"smtpd_spf_check":     "yes please",
		"smtpd_dsns":          "0.0.0.0:25:mail.example.com:true:cert",
		"smtpd_spf_action":    "reject:accept",
		"deliverd_local_ips":  "0.0.0.0&::|192.0.2.1",
		"lda_type":            "internal",
		"rest_server_port":    "70000",
		"db_driver":           "oracle",
	}
	for k, v := range invalid {
		assert.Error(t, ValidateSetting(k, v), "%s=%s", k, v)
	}
}

func TestConfigLoad(t *testing.T) {
	var cfg Config
	require.NoError(t, cfg.Load(map[string]string{"me": "mail.example.com", "smtpd_max_hops": "42"}))
	assert.Equal(t, "mail.example.com", cfg.GetMe())
	assert.Equal(t, 42, cfg.GetSmtpdMaxHops())
	// defaults
	assert.Equal(t, 300, cfg.GetSmtpdServerTimeout())
	assert.Equal(t, "0.0.0.0&::", cfg.GetLocalIps())
	assert.Equal(t, "42", cfg.Values()["smtpd_max_hops"])
	// required: me always, listeners when launched
	require.NoError(t, cfg.Load(map[string]string{}))
	assert.Equal(t, []string{"COCOSMAIL_ME"}, cfg.MissingSettings())
	require.NoError(t, cfg.Load(map[string]string{"me": "m", "smtpd_launch": "true", "pop3d_launch": "true"}))
	assert.Equal(t, []string{"COCOSMAIL_SMTPD_DSNS", "COCOSMAIL_POP3D_DSNS"}, cfg.MissingSettings())
	assert.Error(t, cfg.CheckRequired())
	require.NoError(t, cfg.Load(map[string]string{"me": "m", "smtpd_launch": "true", "smtpd_dsns": "[::1]:25:m:nossl:m", "pop3d_launch": "true", "pop3d_dsns": "[::1]:995:m:ssl:m"}))
	assert.NoError(t, cfg.CheckRequired())
	// invalid value keeps previous config
	assert.Error(t, cfg.Load(map[string]string{"me": "other", "smtpd_max_hops": "x"}))
	assert.Equal(t, "m", cfg.GetMe())
}

func TestSettingsDB(t *testing.T) {
	Logger = logrus.New()
	db, err := gorm.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	// no settings table: nothing stored
	values, err := SettingsFromDB(db)
	require.NoError(t, err)
	assert.Empty(t, values)
	require.NoError(t, db.CreateTable(&DbSetting{}).Error)

	// nothing stored: nothing is filled in, config stays in environment
	require.NoError(t, SettingsFillMissing(db, nil))
	values, _ = SettingsFromDB(db)
	assert.Empty(t, values)

	assert.Error(t, SettingsToDB(db, map[string]string{"db_source": "x.db"}), "bootstrap setting")
	assert.Error(t, SettingsToDB(db, map[string]string{"me": "mail.example.com", "smtpd_max_hops": "x"}))
	values, _ = SettingsFromDB(db)
	assert.Empty(t, values, "nothing saved when a value is invalid")

	require.NoError(t, SettingsToDB(db, map[string]string{"me": "mail.example.com", "smtpd_max_hops": "42"}))
	require.NoError(t, SettingsToDB(db, map[string]string{"smtpd_max_hops": "43"}))
	values, _ = SettingsFromDB(db)
	assert.Equal(t, map[string]string{"me": "mail.example.com", "smtpd_max_hops": "43"}, values)

	// settings in DB: missing ones are added with current value or default, stored ones kept
	require.NoError(t, SettingsFillMissing(db, map[string]string{"smtpd_max_hops": "10", "pop3d_launch": "true"}))
	values, _ = SettingsFromDB(db)
	assert.Len(t, values, len(Settings)-2)
	assert.Equal(t, "43", values["smtpd_max_hops"])
	assert.Equal(t, "true", values["pop3d_launch"])
	assert.Equal(t, "300", values["smtpd_server_timeout"])
	_, hasBootstrap := values["db_driver"]
	assert.False(t, hasBootstrap)

	// setting removed from cocosmail is ignored
	require.NoError(t, db.Save(&DbSetting{Key: "old_setting", Value: "1"}).Error)
	values, err = SettingsFromDB(db)
	require.NoError(t, err)
	_, hasOld := values["old_setting"]
	assert.False(t, hasOld)
}
