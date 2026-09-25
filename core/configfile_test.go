package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stunndard/cocosmail/dist"
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
	f, warnings, err := ParseConfigFile([]byte(old))
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
	in := "# my server\nsettings:\n  me: old.example.com # the name\n\n  # keep me\n  other: 1\nextra: [1]\n"
	f, warnings, err := ParseConfigFile([]byte(in))
	require.NoError(t, err)
	assert.Equal(t, []string{"line 6: other: unknown setting, ignored", "line 7: extra is not a cocosmail section, ignored"}, warnings)
	f.Set("me", "new.example.com")
	f.Set("smtpd_max_hops", "30")
	f.Set("smtpd_launch", "true")
	out := string(f.Bytes())
	assert.True(t, strings.HasPrefix(out, "# my server\nsettings:\n  me: new.example.com # the name\n\n"), out)
	assert.Contains(t, out, "  # keep me\n  other: 1\n")
	assert.Contains(t, out, "# Maximum Received headers")
	assert.Contains(t, out, "smtpd_max_hops: 30\n")
	assert.Contains(t, out, "smtpd_launch: true\n")
	assert.Contains(t, out, "extra: [1]\n")
	assert.Less(t, strings.Index(out, "smtpd_launch"), strings.Index(out, "smtpd_max_hops"), "in the order of settings")

	f.Unset("me")
	_, ok := f.Get("me")
	assert.False(t, ok)
	assert.NotContains(t, string(f.Bytes()), "me:")

	// the same once written again
	f2, _, err := ParseConfigFile(f.Bytes())
	require.NoError(t, err)
	assert.Equal(t, string(f.Bytes()), string(f2.Bytes()))
}

func TestNewConfigFileRoundTrip(t *testing.T) {
	values := map[string]string{"me": "mail.example.com", "smtpd_dsns": "[::]:25:mail.example.com:nossl:cert", "smtpd_max_hops": "true"}
	out := NewConfigFile(values, nil).Bytes()
	for _, line := range strings.Split(string(out), "\n") {
		assert.LessOrEqual(t, len(line), 80, line)
	}
	assert.Contains(t, string(out), "\n# Data sections, e.g.:\n")
	assert.Contains(t, string(out), "  smtpd_launch: false\n")
	assert.Contains(t, string(out), "  smtpd_max_hops: \"true\"\n")
	f, warnings, err := ParseConfigFile(out)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	parsed := f.Values()
	assert.Len(t, parsed, len(Settings))
	assert.Equal(t, "mail.example.com", parsed["me"])
	assert.Equal(t, "300", parsed["smtpd_server_timeout"])
	assert.Equal(t, "true", parsed["smtpd_max_hops"])
	assert.False(t, f.HasData())
	d, err := f.Data()
	require.NoError(t, err)
	assert.True(t, d.Empty())
}

func TestConfigFileData(t *testing.T) {
	key, err := NewDkimKey()
	require.NoError(t, err)
	d := &Data{
		Domains: []DomainData{{Name: "example.com", Local: true}},
		Users:   []UserData{{Login: "john@example.com", PasswordHash: "$2a$10$abc", Mailbox: true}},
		Aliases: []AliasData{{Alias: "sales@example.com", DeliverTo: []string{"john@example.com"}}},
		Dkim:    []DkimData{{Domain: "example.com", Selector: "s1", PrivateKey: key}},
	}
	f := NewConfigFile(map[string]string{"me": "mail.example.com"}, d)
	out := f.Bytes()
	assert.NotContains(t, string(out), "Data sections, e.g.")
	assert.Contains(t, string(out), "\n# Users. password:")
	assert.Contains(t, string(out), "    private_key: |\n      -----BEGIN RSA PRIVATE KEY-----\n")

	f, _, err = ParseConfigFile(out)
	require.NoError(t, err)
	assert.True(t, f.HasData())
	back, err := f.Data()
	require.NoError(t, err)
	assert.Equal(t, d, back)

	// a section removed, the others and their comments kept
	d.Aliases = nil
	d.RelayIPs = []string{"192.0.2.1"}
	f.SetData(d)
	out2 := string(f.Bytes())
	assert.NotContains(t, out2, "aliases:")
	assert.Contains(t, out2, "# Users. password:")
	assert.Contains(t, out2, "relay_ips:\n  - 192.0.2.1\n")

	// misspelled field
	f, _, err = ParseConfigFile([]byte("users:\n  - login: a@b.c\n    pasword: x\n"))
	require.NoError(t, err)
	_, err = f.Data()
	assert.ErrorContains(t, err, "field pasword not found")
}

func TestFlatConfigFileNotWritten(t *testing.T) {
	f, _, err := ParseConfigFile([]byte("# old\nCOCOSMAIL_ME=mail.example.com\n"))
	require.NoError(t, err)
	assert.True(t, f.Flat)
	assert.Equal(t, "mail.example.com", f.Values()["me"])
	assert.ErrorContains(t, f.Write(t.TempDir()+"/x.cfg"), "convert it first")
}

func TestAirComments(t *testing.T) {
	in := "a: 1\n# about b\nb: |\n  line\n  # not a comment\n\n  more\n# about c\nc: 2\n"
	want := "a: 1\n\n# about b\nb: |\n  line\n  # not a comment\n\n  more\n\n# about c\nc: 2\n"
	assert.Equal(t, want, string(airComments([]byte(in))))
}

// dist/conf/cocosmail.yaml.base must have all settings, described as now:
// regenerate it with cocosmail config convert
func TestExampleConfigUpToDate(t *testing.T) {
	base, err := dist.Files.ReadFile("conf/cocosmail.yaml.base")
	require.NoError(t, err)
	f, warnings, err := ParseConfigFile(base)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	assert.Equal(t, string(NewConfigFile(f.Values(), nil).Bytes()), string(base))
}
