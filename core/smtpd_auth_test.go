package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskAuth(t *testing.T) {
	assert.Equal(t, "AUTH PLAIN ********", maskAuth("AUTH PLAIN AGFsaWNlAHNlY3JldA=="))
	assert.Equal(t, "auth login ********", maskAuth("auth login YWxpY2U="))
	assert.Equal(t, "AUTH PLAIN", maskAuth("AUTH PLAIN"))
	assert.Equal(t, "MAIL FROM:<a@example.com>", maskAuth("MAIL FROM:<a@example.com>"))
}
