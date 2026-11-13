package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDkimSignKey(t *testing.T) {
	old := dkimLookupKey
	t.Cleanup(func() { dkimLookupKey = old })
	keys := map[string]*DkimConfig{"example.org": {Domain: "example.org"}, "tenant2.example": {Domain: "tenant2.example"}}
	var looked []string
	dkimLookupKey = func(domain string) (*DkimConfig, error) {
		looked = append(looked, domain)
		return keys[domain], nil
	}
	sign := func(mailFrom, header, helo string) string {
		looked = nil
		d, dkc, err := dkimSignKey(mailFrom, []byte(header), helo)
		require.NoError(t, err)
		if dkc == nil {
			return ""
		}
		return d
	}

	// mail of a user: the key of the sender's domain only
	assert.Equal(t, "example.org", sign("alice@example.org", "From: alice@example.org\r\n\r\n", "mail.example.org"))
	assert.Equal(t, "", sign("alice@sub.example.org", "From: alice@sub.example.org\r\n\r\n", "mail.example.org"))
	assert.Equal(t, []string{"sub.example.org"}, looked)

	// bounce: From domain, then its parent
	bounce := "Date: x\r\nFrom: MAILER-DAEMON@mail.example.org\r\nSubject: failure notice\r\n\r\n"
	assert.Equal(t, "example.org", sign("", bounce, "mail.example.org"))
	assert.Equal(t, []string{"mail.example.org", "example.org"}, looked)
	// no key for the From domain: the HELO name's
	assert.Equal(t, "tenant2.example", sign("", "From: MAILER-DAEMON@mail.other.example\r\n\r\n", "mx.tenant2.example"))
	assert.Equal(t, []string{"mail.other.example", "other.example", "mx.tenant2.example", "tenant2.example"}, looked)
	// none
	assert.Equal(t, "", sign("", "From: MAILER-DAEMON@mail.other.example\r\n\r\n", "localhost"))
}
