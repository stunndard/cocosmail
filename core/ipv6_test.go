package core

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDsnsFromString(t *testing.T) {
	dsns, err := GetDsnsFromString("0.0.0.0:2525:mail.example.com:nossl:example.com;[::]:465:mail.example.com:ssl:example.com;[2001:db8::1]:25:mx.example.com:NoSSL:mx;::1:587:localhost:nossl:local;[fe80::1%Eth0]:25:mx.example.com:nossl:mx")
	assert.NoError(t, err)
	if assert.Len(t, dsns, 5) {
		assert.Equal(t, "0.0.0.0:2525", dsns[0].TcpAddr.String())
		assert.False(t, dsns[0].Ssl)
		assert.Equal(t, "[::]:465", dsns[1].TcpAddr.String())
		assert.True(t, dsns[1].Ssl)
		assert.Equal(t, "[2001:db8::1]:25", dsns[2].TcpAddr.String())
		assert.False(t, dsns[2].Ssl)
		assert.Equal(t, "mx.example.com", dsns[2].SystemName)
		assert.Equal(t, "mx", dsns[2].CertName)
		assert.Equal(t, "[::1]:587", dsns[3].TcpAddr.String())
		// zone keeps its case
		assert.Equal(t, "[fe80::1%Eth0]:25", dsns[4].TcpAddr.String())
	}

	for _, bad := range []string{
		"",
		"0.0.0.0:2525:mail.example.com:nossl",
		"[::1:25:mail.example.com:nossl:cert",
		"999.0.0.1:25:mail.example.com:nossl:cert",
		"[::1]:25::nossl:cert",
		"[::1]:25:mail.example.com:nossl:",
		"[::1]:25:mail.example.com:maybe:cert",
		"[::1]:25:mail.example.com:true:cert",
		"[::1]:25:mail.example.com:false:cert",
	} {
		_, err := GetDsnsFromString(bad)
		assert.Error(t, err, bad)
	}
}

func TestParseIPAndName(t *testing.T) {
	cases := []struct{ in, ip, name string }{
		{"127.0.0.1", "127.0.0.1", ""},
		{"127.0.0.1:mail.example.com", "127.0.0.1", "mail.example.com"},
		{"2001:db8::1", "2001:db8::1", ""},
		{"::", "::", ""},
		{"[2001:db8::1]", "2001:db8::1", ""},
		{"[2001:db8::1]:mail.example.com", "2001:db8::1", "mail.example.com"},
	}
	for _, c := range cases {
		ip, name, err := ParseIPAndName(c.in)
		if assert.NoError(t, err, c.in) {
			assert.Equal(t, c.ip, ip.String(), c.in)
			assert.Equal(t, c.name, name, c.in)
		}
	}
	for _, bad := range []string{"", "mail.example.com", "[2001:db8::1", "[2001:db8::1]mail", "300.1.1.1:mail"} {
		_, _, err := ParseIPAndName(bad)
		assert.Error(t, err, bad)
	}
}

func TestIsIPV4(t *testing.T) {
	assert.True(t, IsIPV4("127.0.0.1"))
	assert.True(t, IsIPV4("0.0.0.0"))
	assert.False(t, IsIPV4("::1"))
	assert.False(t, IsIPV4("2001:db8::1"))
	assert.False(t, IsIPV4("::ffff:192.0.2.1:"))
}

func TestIsAddressLiteral(t *testing.T) {
	assert.True(t, isAddressLiteral("192.0.2.1"))
	assert.True(t, isAddressLiteral("[192.0.2.1]"))
	assert.True(t, isAddressLiteral("[IPv6:2001:db8::1]"))
	assert.True(t, isAddressLiteral("[ipv6:2001:db8::1]"))
	assert.False(t, isAddressLiteral("mail.example.com"))
	assert.False(t, isAddressLiteral("[mail.example.com]"))
}

type strAddr string

func (a strAddr) Network() string { return "tcp" }
func (a strAddr) String() string  { return string(a) }

func TestAddrIP(t *testing.T) {
	assert.Equal(t, "2001:db8::1", AddrIP(&net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 25}).String())
	assert.Equal(t, "fe80::1", AddrIP(&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 25, Zone: "eth0"}).String())
	assert.Equal(t, "fe80::1", AddrIP(strAddr("[fe80::1%eth0]:25")).String())
	assert.Equal(t, "192.0.2.1", AddrIP(strAddr("192.0.2.1:25")).String())
	assert.Nil(t, AddrIP(strAddr("garbage")))
}
