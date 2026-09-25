package core

import (
	"errors"
	"strings"
	"testing"

	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func newDataTestDB(t *testing.T) *gorm.DB {
	Logger = logrus.New()
	db, err := gorm.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	require.NoError(t, db.AutoMigrate(&User{}, &Alias{}, &RcptHost{}, &RelayIpOk{}, &Route{}, &DkimConfig{}, &DbSetting{}).Error)
	return db
}

func testData(t *testing.T) *Data {
	key, err := NewDkimKey()
	require.NoError(t, err)
	return &Data{
		Domains: []DomainData{{Name: "Example.com", Local: true}, {Name: "relay.example.net"}},
		Users: []UserData{
			{Login: "john@example.com", Password: "secret1", Mailbox: true, Relay: true},
			{Login: "info@example.com", Password: "secret2", Mailbox: true, Catchall: true},
			{Login: "sender", Password: "secret3", Relay: true},
		},
		Aliases: []AliasData{
			{Alias: "sales@example.com", DeliverTo: []string{"john@example.com", "info@example.com"}, MiniList: true},
			{Alias: "example.org", DeliverTo: []string{"example.com"}},
		},
		RelayIPs: []string{"192.0.2.1", "2001:DB8::1"},
		Routes:   []RouteData{{Destination: "gmail.com", RemoteHost: "smtp.example.net", Port: 587, Login: "l", Password: "p"}},
		Dkim:     []DkimData{{Domain: "example.com", Selector: "s1", PrivateKey: key}},
	}
}

func TestImportExportData(t *testing.T) {
	db := newDataTestDB(t)
	in := testData(t)

	// dry run writes nothing
	changes, err := ImportData(db, in, false, true)
	require.NoError(t, err)
	assert.Contains(t, changes, "add user john@example.com")
	assert.Contains(t, changes, "add domain example.com")
	empty, err := DataEmpty(db)
	require.NoError(t, err)
	assert.True(t, empty)

	_, err = ImportData(db, in, false, false)
	require.NoError(t, err)
	assert.Equal(t, "secret1", in.Users[0].Password, "the input is not changed")

	out, err := ExportData(db)
	require.NoError(t, err)
	assert.Equal(t, []DomainData{{Name: "example.com", Local: true}, {Name: "relay.example.net"}}, out.Domains)
	require.Len(t, out.Users, 3)
	assert.Equal(t, "info@example.com", out.Users[0].Login)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(out.Users[1].PasswordHash), []byte("secret1")))
	assert.True(t, strings.HasPrefix(out.Users[1].DovecotHash, "$6$"))
	assert.Equal(t, []string{"192.0.2.1", "2001:db8::1"}, out.RelayIPs)
	assert.Equal(t, "example.org", out.Aliases[0].Alias)
	assert.Equal(t, []string{"john@example.com", "info@example.com"}, out.Aliases[1].DeliverTo)
	assert.Equal(t, 587, out.Routes[0].Port)
	assert.Equal(t, "p", out.Routes[0].Password)
	assert.Equal(t, in.Dkim[0].PrivateKey, out.Dkim[0].PrivateKey)

	// domain alias has its rcpthost
	DB = db
	host, err := RcpthostGet("example.org")
	require.NoError(t, err)
	assert.True(t, host.IsAlias)
	var dkim DkimConfig
	require.NoError(t, db.First(&dkim).Error)
	pub, _ := DkimPublicKey(dkim.PrivKey)
	assert.Equal(t, pub, dkim.PubKey)

	// export, import again: nothing changes
	changes, err = ImportData(db, out, true, false)
	require.NoError(t, err)
	assert.Empty(t, changes)
	// the same with clear text passwords
	changes, err = ImportData(db, in, false, false)
	require.NoError(t, err)
	assert.Empty(t, changes)

	// merge without password keeps it
	changes, err = ImportData(db, &Data{Users: []UserData{{Login: "john@example.com", Mailbox: true}}}, false, false)
	require.NoError(t, err)
	assert.Equal(t, []string{"change user john@example.com"}, changes)
	out2, _ := ExportData(db)
	assert.Equal(t, out.Users[1].PasswordHash, out2.Users[1].PasswordHash)
	assert.False(t, out2.Users[1].Relay)

	// exported without secrets: they're kept
	noSecrets, _ := ExportData(db)
	noSecrets.RemoveSecrets()
	changes, err = ImportData(db, noSecrets, true, false)
	require.NoError(t, err)
	assert.Empty(t, changes)

	// replace removes what's not listed
	changes, err = ImportData(db, &Data{Domains: []DomainData{{Name: "example.com", Local: true}}}, true, false)
	require.NoError(t, err)
	assert.Contains(t, changes, "delete user sender")
	out, _ = ExportData(db)
	assert.Equal(t, &Data{Domains: []DomainData{{Name: "example.com", Local: true}}}, out)
	var hosts []RcptHost
	require.NoError(t, db.Find(&hosts).Error)
	assert.Len(t, hosts, 1)
}

func TestImportDataInvalid(t *testing.T) {
	db := newDataTestDB(t)
	in := testData(t)
	in.Domains = in.Domains[1:]
	in.Users = append(in.Users, UserData{Login: "x@relay.example.net", Password: "secret", Mailbox: true})
	in.Aliases = append(in.Aliases, AliasData{Alias: "a@example.com", DeliverTo: []string{"nobody"}})
	in.RelayIPs = append(in.RelayIPs, "1.2.3")
	in.Dkim[0].PrivateKey = "junk"
	_, err := ImportData(db, in, false, false)
	require.Error(t, err)
	for _, msg := range []string{
		"user john@example.com: example.com must be a local domain",
		"user x@relay.example.net: relay.example.net must be a local domain",
		`alias a@example.com: "nobody" is not an email address`,
		"domain alias example.org: example.com must be a local domain",
		`relay IP "1.2.3" is not an IP address`,
		"DKIM of example.com: the private key is not in PEM format",
	} {
		assert.Contains(t, err.Error(), msg)
	}
	empty, _ := DataEmpty(db)
	assert.True(t, empty, "nothing is written")

	_, err = ImportData(db, &Data{Users: []UserData{{Login: "a@b.c", Password: "short"}}}, false, false)
	assert.EqualError(t, err, "user a@b.c: password must be at least 6 chars length")
	_, err = ImportData(db, &Data{Users: []UserData{{Login: "relayonly"}}}, false, false)
	assert.EqualError(t, err, "user relayonly: a password is needed")
}

func TestDkimDNSRecord(t *testing.T) {
	key, err := NewDkimKey()
	require.NoError(t, err)
	name, value, err := DkimDNSRecord(DkimData{Domain: "example.com", Selector: "s1", PrivateKey: key})
	require.NoError(t, err)
	assert.Equal(t, "s1._domainkey.example.com", name)
	assert.True(t, strings.HasPrefix(value, "v=DKIM1;k=rsa;s=email;h=sha256;p=MIGf"), value)
}

func TestEditData(t *testing.T) {
	db := newDataTestDB(t)
	_, err := ImportData(db, testData(t), false, false)
	require.NoError(t, err)
	old, err := ExportData(db)
	require.NoError(t, err)

	// meanwhile, a relay IP is added elsewhere
	_, err = ImportData(db, &Data{RelayIPs: []string{"198.51.100.1"}}, false, false)
	require.NoError(t, err)

	edited := old.Copy()
	edited.RelayIPs = edited.RelayIPs[1:]
	edited.Users[0].Relay = true
	edited.Users = append(edited.Users, UserData{Login: "new@example.com", Password: "secret9", Mailbox: true})
	changes, err := EditData(db, old, edited)
	require.NoError(t, err)
	assert.Equal(t, []string{"change user info@example.com", "add user new@example.com", "delete relay IP 192.0.2.1"}, changes)
	out, _ := ExportData(db)
	assert.Equal(t, []string{"198.51.100.1", "2001:db8::1"}, out.RelayIPs)
	assert.True(t, out.Users[0].Relay)
}

func TestValidateAliases(t *testing.T) {
	hash, _, err := HashPassword("secret1")
	require.NoError(t, err)
	domains := []DomainData{{Name: "example.com", Local: true}}
	// no users: forwards anywhere, to other aliases, to a command
	d := &Data{Domains: domains, Aliases: []AliasData{
		{Alias: "info@example.com", DeliverTo: []string{"someone@elsewhere.example", "sales@example.com"}},
		{Alias: "sales@example.com", Pipe: "/usr/local/bin/tickets"},
	}}
	assert.Empty(t, ValidateData(d))

	// a login without mailbox can have the same address, not a mailbox
	d.Users = []UserData{{Login: "info@example.com", PasswordHash: hash, Relay: true}}
	assert.Empty(t, ValidateData(d))
	d.Users[0].Mailbox = true
	assert.Equal(t, []error{errors.New("alias info@example.com is also a user with a mailbox")}, ValidateData(d))

	for _, c := range []struct {
		alias AliasData
		want  string
	}{
		{AliasData{Alias: "a@elsewhere.example", Pipe: "x"}, "alias a@elsewhere.example: elsewhere.example must be a local domain"},
		{AliasData{Alias: "a@example.com", DeliverTo: []string{"a@example.com"}}, "alias a@example.com can't deliver to itself"},
		{AliasData{Alias: "example.org", Pipe: "x"}, "domain alias example.org must point to one local domain"},
	} {
		alias, want := c.alias, c.want
		errs := ValidateData(&Data{Domains: domains, Aliases: []AliasData{alias}})
		require.Len(t, errs, 1, alias.Alias)
		assert.EqualError(t, errs[0], want)
	}
}

func TestAliasAdd(t *testing.T) {
	db := newDataTestDB(t)
	DB = db
	// no domain, no users: the domain comes with it, forwarding anywhere
	require.NoError(t, AliasAdd("Info@Example.com", "someone@elsewhere.example, sales@example.com", "", true))
	require.NoError(t, AliasAdd("sales@example.com", "", "cat -", false))
	d, err := ExportData(db)
	require.NoError(t, err)
	assert.Equal(t, []DomainData{{Name: "example.com", Local: true}}, d.Domains)
	assert.Equal(t, AliasData{Alias: "info@example.com", DeliverTo: []string{"someone@elsewhere.example", "sales@example.com"}, MiniList: true}, d.Aliases[0])

	assert.EqualError(t, AliasAdd("info@example.com", "a@b.example", "", false), "info@example.com already exists")
	assert.Error(t, AliasAdd("x@example.com", "", "/no/such/command", false))
	assert.EqualError(t, AliasAdd("example.org", "example.net", "", false), "domain alias example.org: example.net must be a local domain")
	require.NoError(t, AliasAdd("example.org", "example.com", "", false))
	host, err := RcpthostGet("example.org")
	require.NoError(t, err)
	assert.True(t, host.IsAlias)

	// a relay domain stays one, its aliases are refused
	_, err = ImportData(db, &Data{Domains: []DomainData{{Name: "relay.example"}}}, false, false)
	require.NoError(t, err)
	assert.EqualError(t, AliasAdd("a@relay.example", "b@elsewhere.example", "", false), "alias a@relay.example: relay.example must be a local domain")
}

func TestExistingErrorsDontBlock(t *testing.T) {
	db := newDataTestDB(t)
	_, err := ImportData(db, testData(t), false, false)
	require.NoError(t, err)
	// domain deleted behind cocosmail's back, e.g. rcpthost del
	require.NoError(t, db.Where("hostname = ?", "example.com").Delete(&RcptHost{}).Error)
	_, err = ImportData(db, &Data{RelayIPs: []string{"198.51.100.7"}}, false, false)
	require.NoError(t, err)
	// but a new problem is refused
	_, err = ImportData(db, &Data{Users: []UserData{{Login: "new@example.com", Password: "secret9", Mailbox: true}}}, false, false)
	assert.ErrorContains(t, err, "user new@example.com: example.com must be a local domain")
}

func TestInitDBPlugins(t *testing.T) {
	db, err := gorm.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, InitDB(db))
	assert.True(t, db.HasTable(&Plugin{}))
	DB = db
	// nothing saved yet: empty, not an error
	j, err := PluginLoadObject("ban", "ips")
	require.NoError(t, err)
	assert.Empty(t, j)
	require.NoError(t, PluginSaveObject("ban", "ips", []byte(`{"a":1}`)))
	require.NoError(t, PluginSaveObject("ban", "ips", []byte(`{"b":2}`)))
	j, err = PluginLoadObject("ban", "ips")
	require.NoError(t, err)
	assert.Equal(t, `{"b":2}`, string(j))
}
