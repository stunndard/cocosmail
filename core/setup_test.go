package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetupSettings(t *testing.T) {
	values := SettingsDefaults()
	for k, v := range SetupSettings("mail.example.com") {
		values[k] = v
	}
	assert.Empty(t, MissingSettings(values))
	assert.Empty(t, ValidateSettings(values))
	dsns, err := GetDsnsFromString(values["smtpd_dsns"])
	assert.NoError(t, err)
	assert.Len(t, dsns, 3)

	assert.Equal(t, "example.com", SetupDomain("mail.example.com"))
	assert.Equal(t, "example.com", SetupDomain("example.com"))
	assert.Equal(t, "b.example.com", SetupDomain("a.b.example.com"))
	assert.True(t, hostnameRe.MatchString("mail.example.com"))
	assert.False(t, hostnameRe.MatchString("localhost"))
	assert.False(t, hostnameRe.MatchString("bad_host.example.com"))
}
