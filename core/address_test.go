package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseReversePath(t *testing.T) {
	for path, want := range map[string]string{
		"<>":                               "",
		"<user@example.com>":               "user@example.com",
		"user@example.com":                 "user@example.com",
		"<first.last+tag@a-b.example.com>": "first.last+tag@a-b.example.com",
		`<"john doe"@example.com>`:         `"john doe"@example.com`,
		`<"a@b"@example.com>`:              `"a@b"@example.com`,
		"<@relay.example.net,@b.example.net:user@example.com>": "user@example.com",
		"<user@[192.0.2.1]>": "user@[192.0.2.1]",
		"<josé@exämple.com>": "josé@exämple.com",
	} {
		got, err := parseReversePath(path)
		if assert.NoError(t, err, path) {
			assert.Equal(t, want, got, path)
		}
	}
	for _, path := range []string{
		"<", ">", "<user@example.com", "user@example.com>", "<<user@example.com>>",
		"<addr@domain@add@domain.com", "<a@gmail.com@gmail.com>",
		"<@gmail.com>", "<user@>", "<user>", "<user@example..com>", "<user@-example.com>",
		"<a..b@example.com>", "<.a@example.com>", "<a.@example.com>", "<a:b@example.com>",
		"<a,b@example.com>", `<"unterminated@example.com>`, `<""@example.com>`,
		"<@relay.example.net>", "<user@exa_mple.com>", "<user@[1.2.3.4>",
	} {
		_, err := parseReversePath(path)
		assert.Error(t, err, path)
	}
}
