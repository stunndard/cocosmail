package core

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSameHostIPs(t *testing.T) {
	a := localIP{ip: net.ParseIP("203.0.113.1"), systemName: "mail.example.com"}
	b := localIP{ip: net.ParseIP("203.0.113.2"), systemName: "mx.tenant2.example"}
	ips := []localIP{a, b}
	assert.Equal(t, []localIP{b}, sameHostIPs(ips, "mx.tenant2.example", "mail.example.com"))
	// a bounce: received by nobody, sent as me
	assert.Equal(t, []localIP{a}, sameHostIPs(ips, "", "mail.example.com"))
	// no IP of that name: all
	assert.Equal(t, ips, sameHostIPs(ips, "other.example", "mail.example.com"))
	assert.Equal(t, ips, sameHostIPs(ips, "", "other.example"))
}
