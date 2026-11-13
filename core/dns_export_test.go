package core

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func dnsTestValues() map[string]string {
	return map[string]string{
		"me":                 "mail.example.com",
		"smtpd_launch":       "true",
		"smtpd_dsns":         ":25:mail.example.com:nossl:t;203.0.113.7:25:mx.tenant2.example:nossl:t2;:465:mail.example.com:ssl:t;127.0.0.1:2525:local:nossl:t",
		"imapd_launch":       "true",
		"imapd_dsns":         ":993:mail.example.com:ssl:t",
		"pop3d_launch":       "false",
		"pop3d_dsns":         ":995:mail.example.com:ssl:t",
		"deliverd_launch":    "true",
		"deliverd_local_ips": "0.0.0.0&::",
		"deliverd_dkim_sign": "true",
	}
}

func dnsTestData() *Data {
	return &Data{
		Domains: []DomainData{{Name: "example.com", Local: true}, {Name: "tenant2.example", Local: true}, {Name: "relay.example"}},
		Users: []UserData{
			{Login: "alice@example.com", Mailbox: true},
			{Login: "postmaster@example.com", Mailbox: true},
			{Login: "bob@tenant2.example", Mailbox: true},
		},
		Aliases: []AliasData{{Alias: "example.net", DeliverTo: []string{"example.com"}}},
		Routes:  []RouteData{{Destination: "remote.test", RemoteHost: "127.0.0.1", LocalIPs: "203.0.113.7:mx.tenant2.example"}},
		Dkim:    []DkimData{{Domain: "example.com", Selector: "sel", DNSName: "sel._domainkey.example.com", DNSRecord: "v=DKIM1;k=rsa;p=KEY"}},
	}
}

func publicHost(v6 bool) net.IP {
	if v6 {
		return net.ParseIP("2001:db8:1::5")
	}
	return net.ParseIP("198.51.100.5")
}

func records(e *DNSExport, name, typ string) (values []string) {
	for _, r := range e.Records {
		if r.Name == name && r.Type == typ {
			values = append(values, r.Value)
		}
	}
	return
}

func TestExportDNS(t *testing.T) {
	e := ExportDNS(dnsTestValues(), dnsTestData(), publicHost)

	// multihome: each domain to its host, others to all hosts on port 25
	assert.Equal(t, []string{"10 mail.example.com"}, records(e, "example.com", "MX"))
	assert.Equal(t, []string{"10 mx.tenant2.example"}, records(e, "tenant2.example", "MX"))
	assert.Equal(t, []string{"10 mail.example.com", "10 mx.tenant2.example"}, records(e, "example.net", "MX"))
	assert.Equal(t, []string{"10 mail.example.com", "10 mx.tenant2.example"}, records(e, "relay.example", "MX"))

	// all addresses: the server's; loopback listener left out
	assert.Equal(t, []string{"198.51.100.5"}, records(e, "mail.example.com", "A"))
	assert.Equal(t, []string{"2001:db8:1::5"}, records(e, "mail.example.com", "AAAA"))
	assert.Equal(t, []string{"203.0.113.7"}, records(e, "mx.tenant2.example", "A"))
	assert.Empty(t, records(e, "local", "A"))

	// outgoing: deliverd_local_ips and the route
	assert.Equal(t, []string{"mail.example.com"}, records(e, "198.51.100.5", "PTR"))
	assert.Equal(t, []string{"mail.example.com"}, records(e, "2001:db8:1::5", "PTR"))
	assert.Equal(t, []string{"mx.tenant2.example"}, records(e, "203.0.113.7", "PTR"))
	spf := "v=spf1 ip4:198.51.100.5 ip6:2001:db8:1::5 ip4:203.0.113.7 -all"
	assert.Equal(t, []string{spf}, records(e, "example.com", "TXT"))
	assert.Equal(t, []string{spf}, records(e, "tenant2.example", "TXT"))
	assert.Empty(t, records(e, "relay.example", "TXT"))
	assert.Equal(t, []string{"v=spf1 a -all"}, records(e, "mail.example.com", "TXT"))

	assert.Equal(t, []string{"v=DKIM1;k=rsa;p=KEY"}, records(e, "sel._domainkey.example.com", "TXT"))
	assert.Equal(t, []string{"v=DMARC1; p=none; rua=mailto:postmaster@example.com"}, records(e, "_dmarc.example.com", "TXT"))
	assert.Equal(t, []string{"v=DMARC1; p=none"}, records(e, "_dmarc.tenant2.example", "TXT"))
	data := dnsTestData()
	data.Aliases = append(data.Aliases, AliasData{Alias: "dmarc@tenant2.example", DeliverTo: []string{"bob@tenant2.example"}})
	assert.Equal(t, []string{"v=DMARC1; p=none; rua=mailto:dmarc@tenant2.example"},
		records(ExportDNS(dnsTestValues(), data, publicHost), "_dmarc.tenant2.example", "TXT"))

	// clients: submission over TLS and IMAP, not POP3 (off)
	assert.Equal(t, []string{"0 1 465 mail.example.com"}, records(e, "_submissions._tcp.example.com", "SRV"))
	assert.Equal(t, []string{"0 1 993 mail.example.com"}, records(e, "_imaps._tcp.tenant2.example", "SRV"))
	assert.Empty(t, records(e, "_pop3s._tcp.example.com", "SRV"))

	text := e.Text()
	assert.Contains(t, text, "tenant2.example has no DKIM key")
	// MAILER-DAEMON@mail.example.com: the key of example.com
	assert.NotContains(t, text, "Bounces aren't DKIM signed")
	assert.Contains(t, text, "\nexample.com\n")
	assert.Regexp(t, `\n  MX +@ +10 mail.example.com\n`, text)
	assert.Regexp(t, `\n  A +mail +198.51.100.5\n`, text)
	assert.Regexp(t, `\n  TXT +sel._domainkey +v=DKIM1;k=rsa;p=KEY\n`, text)
	assert.Regexp(t, `\n  203.0.113.7 +mx.tenant2.example\n`, text)
}

func TestExportDNSPrivate(t *testing.T) {
	// behind NAT, no IPv6
	e := ExportDNS(dnsTestValues(), dnsTestData(), func(v6 bool) net.IP {
		if v6 {
			return nil
		}
		return net.ParseIP("192.168.1.10")
	})
	assert.Equal(t, []string{dnsPublicIPv4}, records(e, "mail.example.com", "A"))
	assert.Empty(t, records(e, "mail.example.com", "AAAA"))
	assert.Equal(t, []string{"mail.example.com"}, records(e, dnsPublicIPv4, "PTR"))
	assert.Contains(t, e.Text(), "192.168.1.10 is private")

	data := dnsTestData()
	data.Dkim = nil
	assert.Contains(t, ExportDNS(dnsTestValues(), data, publicHost).Text(),
		"Bounces aren't DKIM signed: no key for mail.example.com, the HELO names or their parent domains.")

	// deliverd off: nothing for outgoing mail
	values := dnsTestValues()
	values["deliverd_launch"] = "false"
	e = ExportDNS(values, dnsTestData(), publicHost)
	assert.Empty(t, records(e, "example.com", "TXT"))
	assert.Equal(t, []string{"10 mail.example.com"}, records(e, "example.com", "MX"))
	assert.Empty(t, records(e, "mail.example.com", "TXT"))
	// the MX hosts still get theirs
	assert.Equal(t, []string{"mail.example.com"}, records(e, "198.51.100.5", "PTR"))
	assert.True(t, strings.Contains(e.Text(), "COCOSMAIL_DELIVERD_LAUNCH is off"))
}

// fakeDNS answers lookups from maps, not found otherwise
type fakeDNS struct {
	mx  map[string][]*net.MX
	txt map[string][]string
	ip  map[string][]string
	srv map[string][]*net.SRV
	ptr map[string][]string
	err map[string]error
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	name = strings.TrimSuffix(name, ".")
	if v, ok := f.mx[name]; ok {
		return v, nil
	}
	return nil, notFound(name)
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".")
	if err := f.err[name]; err != nil {
		return nil, err
	}
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, notFound(name)
}

func (f *fakeDNS) LookupIPAddr(_ context.Context, host string) (addrs []net.IPAddr, err error) {
	host = strings.TrimSuffix(host, ".")
	for _, a := range f.ip[host] {
		addrs = append(addrs, net.IPAddr{IP: net.ParseIP(a)})
	}
	if len(addrs) == 0 {
		return nil, notFound(host)
	}
	return addrs, nil
}

func (f *fakeDNS) LookupSRV(_ context.Context, _, _, name string) (string, []*net.SRV, error) {
	name = strings.TrimSuffix(name, ".")
	if v, ok := f.srv[name]; ok {
		return name, v, nil
	}
	return "", nil, notFound(name)
}

func (f *fakeDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if v, ok := f.ptr[addr]; ok {
		return v, nil
	}
	return nil, notFound(addr)
}

func status(e *DNSExport, name, typ string) (s, found string) {
	for _, r := range e.Records {
		if r.Name == name && r.Type == typ {
			return r.Status, r.Found
		}
	}
	return "no record", ""
}

func TestCheckDNS(t *testing.T) {
	e := ExportDNS(dnsTestValues(), dnsTestData(), publicHost)
	dns := &fakeDNS{
		mx: map[string][]*net.MX{
			"example.com":     {{Host: "MAIL.example.com.", Pref: 10}},
			"tenant2.example": {{Host: "mx.tenant2.example.", Pref: 20}},
		},
		ip: map[string][]string{
			"mail.example.com":   {"198.51.100.5", "2001:db8:1::6"},
			"mx.tenant2.example": {"203.0.113.7"},
		},
		txt: map[string][]string{
			"example.com":                {"google-site-verification=x", "v=spf1  ip4:198.51.100.5 ip6:2001:db8:1::5 ip4:203.0.113.7 -all"},
			"tenant2.example":            {"v=spf1 mx -all", "v=spf1 a -all"},
			"sel._domainkey.example.com": {"k=rsa; p=K EY"},
			"_dmarc.example.com":         {"v=DMARC1; p=reject"},
		},
		srv: map[string][]*net.SRV{
			"_imaps._tcp.example.com":       {{Target: "mail.example.com.", Port: 993, Priority: 5, Weight: 0}},
			"_submissions._tcp.example.com": {{Target: "mail.example.com.", Port: 587}},
		},
		ptr: map[string][]string{"198.51.100.5": {"mail.example.com."}, "203.0.113.7": {"host-7.provider.example."}},
		err: map[string]error{"_dmarc.tenant2.example": &net.DNSError{Err: "server misbehaving", Name: "_dmarc.tenant2.example", IsTemporary: true}},
	}
	problems := e.Check(dns)

	for _, c := range []struct{ name, typ, status, found string }{
		{"example.com", "MX", DNSOk, ""},
		{"tenant2.example", "MX", DNSDifferent, "20 mx.tenant2.example"},
		{"example.net", "MX", DNSMissing, ""},
		{"mail.example.com", "A", DNSOk, ""},
		{"mail.example.com", "AAAA", DNSDifferent, "2001:db8:1::6"},
		{"example.com", "TXT", DNSOk, ""},
		{"tenant2.example", "TXT", DNSDifferent, "2 records, only one is allowed: v=spf1 mx -all | v=spf1 a -all"},
		{"sel._domainkey.example.com", "TXT", DNSOk, ""},
		{"_dmarc.example.com", "TXT", DNSOk, "v=DMARC1; p=reject"},
		{"_dmarc.tenant2.example", "TXT", DNSError, "lookup _dmarc.tenant2.example: server misbehaving"},
		{"_imaps._tcp.example.com", "SRV", DNSOk, ""},
		{"_submissions._tcp.example.com", "SRV", DNSDifferent, "0 0 587 mail.example.com"},
		{"198.51.100.5", "PTR", DNSOk, ""},
		{"203.0.113.7", "PTR", DNSDifferent, "host-7.provider.example"},
		{"2001:db8:1::5", "PTR", DNSMissing, ""},
	} {
		s, found := status(e, c.name, c.typ)
		assert.Equal(t, c.status, s, c.name+" "+c.typ)
		assert.Equal(t, c.found, found, c.name+" "+c.typ)
	}
	assert.Greater(t, problems, 5)

	text := e.Text()
	assert.Regexp(t, `\n  ok +MX +@ +10 mail.example.com\n`, text)
	assert.Regexp(t, `\n  DIFFERENT +MX +@ +10 mx.tenant2.example\n +found: 20 mx.tenant2.example\n`, text)
	assert.Regexp(t, `\n\d+ ok, \d+ missing, \d+ different, 1 error, \d+ optional\n$`, text)
	s, _ := status(e, "mail.example.com", "TXT")
	assert.Equal(t, DNSMissing, s)
	var found string

	// placeholder: fill in, what's there is shown
	e = ExportDNS(dnsTestValues(), dnsTestData(), func(v6 bool) net.IP { return nil })
	e.Check(dns)
	s, found = status(e, "mail.example.com", "A")
	assert.Equal(t, DNSFillIn, s)
	assert.Equal(t, "198.51.100.5", found)
	s, _ = status(e, dnsPublicIPv4, "PTR")
	assert.Equal(t, DNSFillIn, s)
}

func TestZoneFiles(t *testing.T) {
	data := dnsTestData()
	data.Dkim[0].DNSRecord = "v=DKIM1;k=rsa;p=" + strings.Repeat("A", 300)
	values := dnsTestValues()
	values["smtpd_dsns"] += ";198.51.100.9:25:mx.other.org:nossl:t"
	e := ExportDNS(values, data, publicHost)
	names, files := e.ZoneFiles()
	assert.Equal(t, []string{"example.com", "example.net", "relay.example", "tenant2.example", "other.org"}, names)

	z := files["example.com"]
	assert.Contains(t, z, "$ORIGIN example.com.\n$TTL 3600\n")
	assert.Regexp(t, `\n@ +IN  MX    10 mail.example.com.\n`, z)
	assert.Regexp(t, `\nmail +IN  A     198.51.100.5\n`, z)
	assert.Regexp(t, `\n_imaps._tcp +IN  SRV   0 1 993 mail.example.com.\n`, z)
	assert.Contains(t, z, `IN  TXT   "v=DKIM1;k=rsa;p=`+strings.Repeat("A", 255-16)+`" "`+strings.Repeat("A", 300-255+16)+`"`)
	assert.Regexp(t, `\nmx +IN  A     198.51.100.9\n`, files["other.org"])

	assert.Contains(t, e.ReverseText(), "; 5.100.51.198.in-addr.arpa.  IN  PTR  mail.example.com.\n")
	assert.Contains(t, e.ReverseText(), "; 5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.  IN  PTR  mail.example.com.\n")

	// unknown address: commented out
	e = ExportDNS(values, data, func(v6 bool) net.IP { return nil })
	_, files = e.ZoneFiles()
	assert.Contains(t, files["example.com"], "; fill in the address, then remove the ; of the record\n; mail")
}

// another SPF record allowing the same addresses is ok
func TestCheckSPF(t *testing.T) {
	values := dnsTestValues()
	values["deliverd_local_ips"] = "0.0.0.0"
	data := dnsTestData()
	data.Routes = nil
	dns := &fakeDNS{
		mx: map[string][]*net.MX{"example.com": {{Host: "mail.example.com.", Pref: 10}}},
		ip: map[string][]string{"mail.example.com": {"198.51.100.5"}},
		txt: map[string][]string{
			"example.com":      {"v=spf1 mx -all"},
			"tenant2.example":  {"v=spf1 ip4:203.0.113.0/24 -all"},
			"mail.example.com": {"v=spf1 a ~all"},
		},
	}
	e := ExportDNS(values, data, publicHost)
	e.Check(dns)
	s, found := status(e, "example.com", "TXT")
	assert.Equal(t, DNSOk, s)
	assert.Equal(t, "v=spf1 mx -all (allows the same addresses)", found)
	s, found = status(e, "mail.example.com", "TXT")
	assert.Equal(t, DNSOk, s)
	assert.Equal(t, "v=spf1 a ~all (allows the same addresses)", found)
	s, found = status(e, "tenant2.example", "TXT")
	assert.Equal(t, DNSDifferent, s)
	assert.Equal(t, "v=spf1 ip4:203.0.113.0/24 -all; 198.51.100.5: fail", found)
}
