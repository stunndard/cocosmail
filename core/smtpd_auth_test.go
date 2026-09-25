package core

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskAuth(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	assert.Equal(t, "AUTH PLAIN alice@example.com ********", maskAuth("AUTH PLAIN "+b64("\x00alice@example.com\x00secret")))
	assert.Equal(t, "AUTH PLAIN admin alice@example.com ********", maskAuth("AUTH PLAIN "+b64("admin\x00alice@example.com\x00secret")))
	assert.Equal(t, "AUTH PLAIN ********", maskAuth("AUTH PLAIN not-base64"))
	assert.Equal(t, "AUTH PLAIN ********", maskAuth("AUTH PLAIN "+b64("no separators")))
	// LOGIN initial response is the username
	assert.Equal(t, "auth login "+b64("alice"), maskAuth("auth login "+b64("alice")))
	assert.Equal(t, "AUTH XOAUTH2 ********", maskAuth("AUTH XOAUTH2 dG9rZW4="))
	assert.Equal(t, "AUTH PLAIN", maskAuth("AUTH PLAIN"))
	assert.Equal(t, "MAIL FROM:<a@example.com>", maskAuth("MAIL FROM:<a@example.com>"))

	assert.Equal(t, "alice@example.com ********", maskAuthPlain(b64("\x00alice@example.com\x00secret")))
	assert.Equal(t, "alice ********", maskCramMD5(b64("alice 0123456789abcdef")))
	assert.Equal(t, "********", maskCramMD5(b64("nospace")))
}
