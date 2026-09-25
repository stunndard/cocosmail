package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigFileOldStyle(t *testing.T) {
	old := `#!/bin/sh
# Who am i
export COCOSMAIL_ME="mail.example.com"
export COCOSMAIL_BASE_PATH=""
export COCOSMAIL_SMTPD_LAUNCH=true;
export COCOSMAIL_SMTPD_DSNS='0.0.0.0:25:mail.example.com:false:cert'
export OS_AUTH_URL=https://auth.example.com
COCOSMAIL_SMTPD_MAX_HOPS=10
COCOSMAIL_SMTPD_MAX_HOPS=30
garbage line
`
	f, warnings, err := ParseConfigFile(strings.NewReader(old))
	require.NoError(t, err)
	values := f.Values()
	assert.Equal(t, "mail.example.com", values["me"])
	assert.Equal(t, "0.0.0.0:25:mail.example.com:false:cert", values["smtpd_dsns"])
	assert.Equal(t, "30", values["smtpd_max_hops"])
	// shell statement end is not part of the value
	assert.Equal(t, "true", values["smtpd_launch"])
	joined := strings.Join(warnings, "\n")
	assert.Contains(t, joined, "COCOSMAIL_BASE_PATH: not used anymore")
	assert.Contains(t, joined, "OS_AUTH_URL is not a cocosmail setting")
	assert.Contains(t, joined, "already set on line 8")
	assert.Contains(t, joined, "not KEY=value")

	notes := UpgradeLegacyValues(values)
	assert.Len(t, notes, 1)
	assert.Equal(t, "0.0.0.0:25:mail.example.com:nossl:cert", values["smtpd_dsns"])
}

func TestConfigFileKeepsComments(t *testing.T) {
	in := "# my server\nCOCOSMAIL_ME=old.example.com\n\n# keep me\nOTHER=1\n"
	f, _, err := ParseConfigFile(strings.NewReader(in))
	require.NoError(t, err)
	f.Set("me", "new.example.com")
	f.Set("smtpd_max_hops", "30")
	out := string(f.Bytes())
	assert.True(t, strings.HasPrefix(out, "# my server\nCOCOSMAIL_ME=new.example.com\n\n# keep me\nOTHER=1\n"), out)
	assert.Contains(t, out, "# Maximum Received headers")
	assert.True(t, strings.HasSuffix(out, "COCOSMAIL_SMTPD_MAX_HOPS=30\n"), out)

	f.Unset("me")
	_, ok := f.Get("me")
	assert.False(t, ok)
	assert.NotContains(t, string(f.Bytes()), "COCOSMAIL_ME=")
}

func TestNewConfigFileRoundTrip(t *testing.T) {
	values := map[string]string{"me": "mail.example.com", "smtpd_dsns": "[::]:25:mail.example.com:nossl:cert"}
	out := NewConfigFile(values).Bytes()
	for _, line := range strings.Split(string(out), "\n") {
		assert.False(t, strings.Contains(line, "export") || strings.Contains(line, `"`) && !strings.HasPrefix(line, "#"), line)
		assert.LessOrEqual(t, len(line), 80, line)
	}
	f, warnings, err := ParseConfigFile(strings.NewReader(string(out)))
	require.NoError(t, err)
	assert.Empty(t, warnings)
	parsed := f.Values()
	assert.Len(t, parsed, len(Settings))
	assert.Equal(t, "mail.example.com", parsed["me"])
	assert.Equal(t, "300", parsed["smtpd_server_timeout"])
	assert.Empty(t, ValidateSettings(parsed))
}
