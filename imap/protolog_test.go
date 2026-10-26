package imap

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func logged(client bool, chunks ...string) []string {
	var lines []string
	l := &protoLog{dir: "> ", client: client, log: func(s string) { lines = append(lines, s) }}
	if client {
		l.dir = "< "
	}
	for _, c := range chunks {
		_, _ = l.Write([]byte(c))
	}
	return lines
}

func TestProtoLogLines(t *testing.T) {
	assert.Equal(t, []string{"< a1 NOOP", "< a2 SELECT INBOX"},
		logged(true, "a1 NO", "OP\r\na2 SELECT INBOX\r", "\n"))
	// literals by size only, the line goes on after them
	assert.Equal(t, []string{
		"> * 1 FETCH (UID 4 BODY[] {12}", "> (literal, 12 bytes)", "> )", "> a1 OK FETCH completed",
	}, logged(false, "* 1 FETCH (UID 4 BODY[] {12}\r\nSubject: x\r\n", ")\r\na1 OK FETCH completed\r\n"))
	assert.Equal(t, []string{"< a1 APPEND INBOX ~{5+}", "< (literal, 5 bytes)", "< a2 NOOP"},
		logged(true, "a1 APPEND INBOX ~{5+}\r\nhel", "lo\r\na2 NOOP\r\n"))
	// long lines are cut, a literal at their end is still seen
	long := "* SEARCH " + strings.Repeat("1 ", 1000)
	got := logged(false, long+"{3}\r\nabc\r\n")
	assert.Len(t, got, 2)
	assert.True(t, strings.HasSuffix(got[0], " ... {3}"), got[0])
	assert.Equal(t, "> (literal, 3 bytes)", got[1])
}

func TestProtoLogPasswords(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("\x00alice@example.com\x00secret"))
	for _, c := range []struct{ in, want string }{
		{"a1 LOGIN alice secret\r\n", "< a1 LOGIN alice ********"},
		{"a1 login \"al ice\" \"sec \\\" ret\"\r\n", "< a1 login \"al ice\" ********"},
		{"a1 AUTHENTICATE PLAIN " + plain + "\r\n", "< a1 AUTHENTICATE PLAIN alice@example.com ********"},
		{"a1 AUTHENTICATE XOAUTH2 dG9rZW4=\r\n", "< a1 AUTHENTICATE XOAUTH2 ********"},
	} {
		assert.Equal(t, []string{c.want}, logged(true, c.in))
	}
	// SASL response on its own line
	assert.Equal(t, []string{"< a1 AUTHENTICATE PLAIN", "< alice@example.com ********", "< a2 NOOP"},
		logged(true, "a1 AUTHENTICATE PLAIN\r\n", plain+"\r\n", "a2 NOOP\r\n"))
	// username and password literals
	assert.Equal(t, []string{"< a1 LOGIN {5}", "< (literal, 5 bytes)", "<  ********"},
		logged(true, "a1 LOGIN {5}\r\n", "alice secret\r\n"))
	assert.Equal(t, []string{"< a1 LOGIN {5}", "< (literal, 5 bytes)", "<  {6}", "< (literal, 6 bytes)"},
		logged(true, "a1 LOGIN {5}\r\nalice {6}\r\nsecret\r\n"))
	assert.Equal(t, []string{"< a1 LOGIN alice {6}", "< (literal, 6 bytes)"},
		logged(true, "a1 LOGIN alice {6}\r\nsecret\r\n"))
}
